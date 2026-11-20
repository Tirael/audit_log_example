using AuditLog.Anchoring;
using AuditLog.Canonical;
using AuditLog.Merkle;
using LinqToDB;
using LinqToDB.Async;
using Orders.Api.Data;

namespace Orders.Api.Services;

public sealed record VerificationFinding(string Code, string Message, long? LeafIndex = null, long? CheckpointSeq = null);

public sealed record VerificationReport(
    bool Ok,
    long TreeSize,
    int EntryCount,
    int CheckpointCount,
    IReadOnlyList<VerificationFinding> Findings)
{
    public long? FirstBadLeaf => Findings.Select(f => f.LeafIndex).FirstOrDefault(i => i is not null);
}

/// <summary>
/// Independently re-checks the journal. Nothing stored next to the log is trusted:
/// every canonical entry, leaf hash and root is recomputed from the raw columns, then compared with the
/// checkpoints in the database, with the signed checkpoints in Vault and with Vault's heads pointer.
/// </summary>
public sealed class VerificationService(AuditDbFactory dbFactory, ICheckpointStore store)
{
    public async Task<VerificationReport> VerifyAsync(CancellationToken cancellationToken)
    {
        var findings = new List<VerificationFinding>();

        await using var db = dbFactory.Create();

        var entries = await db.GetTable<AuditLogRecord>()
            .Where(r => r.Ledger == AuditDb.LedgerName)
            .OrderBy(r => r.LeafIndex)
            .ToListAsync(cancellationToken);

        var checkpoints = await db.GetTable<AuditCheckpointRecord>()
            .Where(c => c.Ledger == AuditDb.LedgerName)
            .OrderBy(c => c.Seq)
            .ToListAsync(cancellationToken);

        // Rebuilding the log stops at the first entry that cannot be trusted: every later comparison
        // would only repeat the same conclusion, so the first finding is the useful one.
        var leaves = new List<byte[]>(entries.Count);
        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];

            if (entry.LeafIndex != i)
            {
                findings.Add(new VerificationFinding(
                    "leaf_index_gap",
                    $"Expected leaf index {i} but found {entry.LeafIndex}: entries were deleted, inserted or reordered.",
                    i));
                return Incomplete(entries, checkpoints, findings);
            }

            var expectedFields = new AuditEventFields(
                entry.Ledger,
                entry.CreatedAt,
                entry.Actor,
                entry.Action,
                entry.EntityType,
                entry.EntityId.ToString("D"),
                entry.FromStatus,
                entry.ToStatus,
                AuditCanonicalizer.HashData(entry.DataCanonical));

            var recomputedCanonical = AuditCanonicalizer.Canonicalize(expectedFields);
            if (!recomputedCanonical.AsSpan().SequenceEqual(entry.Canonical))
            {
                findings.Add(new VerificationFinding(
                    "canonical_payload_mismatch",
                    "Stored fields do not re-encode to the canonical bytes that were hashed.",
                    entry.LeafIndex));
                return Incomplete(entries, checkpoints, findings);
            }

            var recomputedLeaf = MerkleHash.Leaf(recomputedCanonical);
            if (!recomputedLeaf.AsSpan().SequenceEqual(entry.LeafHash))
            {
                findings.Add(new VerificationFinding(
                    "leaf_hash_mismatch",
                    "The stored leaf hash does not match SHA-256 of the canonical entry.",
                    entry.LeafIndex));
                return Incomplete(entries, checkpoints, findings);
            }

            leaves.Add(recomputedLeaf);
        }

        var rootsBySize = ComputeRootsAtCheckpointSizes(leaves, checkpoints);

        var publicKeys = new Dictionary<int, string>();
        var expectedSeq = 1L;
        byte[]? previousHash = null;
        var lastCheckpointSeq = 0L;

        foreach (var checkpoint in checkpoints)
        {
            if (checkpoint.Seq != expectedSeq)
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_sequence_gap",
                    $"Expected checkpoint {expectedSeq} but found {checkpoint.Seq}.",
                    CheckpointSeq: checkpoint.Seq));
            }

            if (!BytesEqual(checkpoint.PreviousCheckpointHash, previousHash))
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_chain_broken",
                    "Checkpoint does not reference the previous checkpoint payload hash.",
                    CheckpointSeq: checkpoint.Seq));
            }

            var recomputedPayloadHash = CheckpointCodec.HashPayload(checkpoint.Payload);
            if (!recomputedPayloadHash.AsSpan().SequenceEqual(checkpoint.PayloadHash))
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_payload_hash_mismatch",
                    "Stored checkpoint payload does not hash to the stored payload hash.",
                    CheckpointSeq: checkpoint.Seq));
            }

            long? badLeaf = null;
            if (!rootsBySize.TryGetValue(checkpoint.TreeSize, out var recomputedRoot))
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_beyond_log",
                    $"Checkpoint claims tree size {checkpoint.TreeSize} but the log has {leaves.Count} entries.",
                    CheckpointSeq: checkpoint.Seq));
                badLeaf = leaves.Count;
            }
            else if (!recomputedRoot.AsSpan().SequenceEqual(checkpoint.Root))
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_root_mismatch",
                    $"Recomputed Merkle root for tree size {checkpoint.TreeSize} does not match the checkpoint.",
                    LeafIndex: checkpoint.TreeSize - 1,
                    CheckpointSeq: checkpoint.Seq));
                badLeaf = checkpoint.TreeSize - 1;
            }

            var anchored = await store.ReadCheckpointAsync(
                checkpoint.Ledger, checkpoint.Seq, checkpoint.CreatedAt, cancellationToken);

            if (anchored is null)
            {
                findings.Add(new VerificationFinding(
                    "checkpoint_missing_in_vault",
                    "Checkpoint exists in the database but not in the anchor store.",
                    CheckpointSeq: checkpoint.Seq));
            }
            else
            {
                if (!anchored.Payload.AsSpan().SequenceEqual(checkpoint.Payload))
                {
                    findings.Add(new VerificationFinding(
                        "checkpoint_payload_mismatch",
                        "Anchored checkpoint payload differs from the database copy.",
                        CheckpointSeq: checkpoint.Seq));
                }

                if (!anchored.Signature.AsSpan().SequenceEqual(checkpoint.Signature))
                {
                    findings.Add(new VerificationFinding(
                        "checkpoint_signature_mismatch",
                        "Anchored signature differs from the database copy.",
                        CheckpointSeq: checkpoint.Seq));
                }

                if (!publicKeys.TryGetValue(anchored.KeyVersion, out var pem))
                {
                    var publicKey = await store.ReadPublicKeyAsync(anchored.KeyVersion, cancellationToken);
                    pem = publicKey.Pem;
                    publicKeys[anchored.KeyVersion] = pem;
                }

                if (!CheckpointSignature.Verify(checkpoint.Payload, checkpoint.Signature, pem))
                {
                    findings.Add(new VerificationFinding(
                        "checkpoint_signature_invalid",
                        $"Transit signature (key version {anchored.KeyVersion}) does not verify.",
                        CheckpointSeq: checkpoint.Seq));
                }
            }

            previousHash = checkpoint.PayloadHash;
            lastCheckpointSeq = checkpoint.Seq;
            expectedSeq = checkpoint.Seq + 1;
        }

        // Entries are only ever written together with their checkpoint, so anything past the newest
        // anchored tree size was appended outside the application: refuse to call the journal intact.
        var anchoredSize = checkpoints.Count == 0 ? 0 : checkpoints[^1].TreeSize;
        if (leaves.Count > anchoredSize)
        {
            findings.Add(new VerificationFinding(
                "unanchored_entries",
                $"{leaves.Count - anchoredSize} entries are not covered by any checkpoint.",
                LeafIndex: anchoredSize,
                CheckpointSeq: lastCheckpointSeq));
        }

        var heads = await store.ReadHeadsAsync(AuditDb.LedgerName, cancellationToken);        if (heads is null)
        {
            findings.Add(new VerificationFinding(
                "anchors_missing",
                "Vault has no heads pointer for this ledger."));
        }
        else if (heads.TreeSize > leaves.Count)
        {
            findings.Add(new VerificationFinding(
                "database_rolled_back",
                $"Vault anchors a tree of size {heads.TreeSize} but the database only has {leaves.Count} entries: " +
                "the database was rolled back behind its anchors.",
                LeafIndex: leaves.Count,
                CheckpointSeq: heads.Seq));
        }
        else if (heads.Seq > lastCheckpointSeq)
        {
            findings.Add(new VerificationFinding(
                "anchor_ahead_of_database",
                $"Vault heads point at checkpoint {heads.Seq}, the database has {lastCheckpointSeq}. " +
                "A write may have failed after anchoring; the next successful write repairs this.",
                CheckpointSeq: heads.Seq));
        }
        else
        {
            var last = checkpoints.LastOrDefault();
            if (last is not null
                && (!heads.Root.AsSpan().SequenceEqual(last.Root) || !heads.CheckpointHash.AsSpan().SequenceEqual(last.PayloadHash)))
            {
                findings.Add(new VerificationFinding(
                    "anchor_heads_mismatch",
                    "Vault heads do not match the newest database checkpoint.",
                    CheckpointSeq: last.Seq));
            }
        }

        return new VerificationReport(
            Ok: findings.Count == 0,
            TreeSize: leaves.Count,
            EntryCount: entries.Count,
            CheckpointCount: checkpoints.Count,
            Findings: findings);
    }

    private static VerificationReport Incomplete(
        List<AuditLogRecord> entries, List<AuditCheckpointRecord> checkpoints, List<VerificationFinding> findings) =>
        new(
            Ok: false,
            TreeSize: entries.Count,
            EntryCount: entries.Count,
            CheckpointCount: checkpoints.Count,
            Findings: findings);

    private static Dictionary<long, byte[]> ComputeRootsAtCheckpointSizes(
        List<byte[]> leaves, List<AuditCheckpointRecord> checkpoints)
    {
        var roots = new Dictionary<long, byte[]>();
        if (checkpoints.Count == 0)
            return roots;

        var frontier = MerkleFrontier.Empty;
        var next = 0;
        foreach (var leaf in leaves)
        {
            frontier.Append(leaf);
            while (next < checkpoints.Count && checkpoints[next].TreeSize <= frontier.Size)
            {
                if (checkpoints[next].TreeSize == frontier.Size)
                    roots[frontier.Size] = frontier.Root();
                next++;
            }

            if (next == checkpoints.Count)
                break;
        }

        return roots;
    }

    private static bool BytesEqual(byte[]? left, byte[]? right) =>
        left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);
}

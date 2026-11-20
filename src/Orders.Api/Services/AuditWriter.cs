using AuditLog.Anchoring;
using AuditLog.Canonical;
using AuditLog.Merkle;
using LinqToDB;
using LinqToDB.Async;
using LinqToDB.Data;
using Orders.Api.Data;

namespace Orders.Api.Services;

public sealed record PendingAuditEvent(
    string Action,
    string EntityType,
    Guid EntityId,
    string? FromStatus,
    string? ToStatus,
    byte[] Data);

/// <summary>
/// Appends entries to the Merkle log and anchors the resulting root in Vault <em>before</em> the
/// caller's database transaction commits. If Vault refuses, the exception bubbles up and the whole
/// transaction — business change and audit row alike — is rolled back.
/// </summary>
public sealed class AuditWriter(ICheckpointStore store, TimeProvider clock)
{
    public static async Task EnsureLedgerAsync(AuditDbFactory dbFactory, CancellationToken cancellationToken = default)
    {
        await using var db = dbFactory.Create();
        var exists = await db.GetTable<AuditLedgerRecord>()
            .AnyAsync(l => l.Ledger == AuditDb.LedgerName, cancellationToken);
        if (exists)
            return;

        await db.InsertAsync(
            new AuditLedgerRecord
            {
                Ledger = AuditDb.LedgerName,
                TreeSize = 0,
                Frontier = FrontierCodec.Encode(MerkleFrontier.Empty),
                LastCheckpointSeq = 0,
                PreviousCheckpointHash = null
            },
            token: cancellationToken);
    }

    /// <summary>Returns the checkpoint sequence number that now covers the appended entries.</summary>
    public async Task<long> AppendAsync(
        DataConnection db,
        string actor,
        IReadOnlyList<PendingAuditEvent> events,
        CancellationToken cancellationToken)
    {
        if (events.Count == 0)
            throw new ArgumentException("At least one audit event is required.", nameof(events));

        // Serializes appends: dense leaf indices and a consistent frontier depend on one writer at a time.
        var ledger = db.Query<AuditLedgerRecord>(
                "SELECT * FROM audit_ledger WHERE ledger = @ledger FOR UPDATE",
                new { ledger = AuditDb.LedgerName })
            .Single();

        var frontier = FrontierCodec.Decode(ledger.Frontier, ledger.TreeSize);
        var timestamp = TruncateToMicroseconds(clock.GetUtcNow());

        foreach (var pending in events)
        {
            var fields = new AuditEventFields(
                AuditDb.LedgerName,
                timestamp,
                actor,
                pending.Action,
                pending.EntityType,
                pending.EntityId.ToString("D"),
                pending.FromStatus,
                pending.ToStatus,
                AuditCanonicalizer.HashData(pending.Data));

            var canonical = AuditCanonicalizer.Canonicalize(fields);
            var leafHash = MerkleHash.Leaf(canonical);

            var record = new AuditLogRecord
            {
                LeafIndex = frontier.Size,
                Id = Guid.CreateVersion7(),
                Ledger = AuditDb.LedgerName,
                Actor = actor,
                Action = pending.Action,
                EntityType = pending.EntityType,
                EntityId = pending.EntityId,
                FromStatus = pending.FromStatus,
                ToStatus = pending.ToStatus,
                DataCanonical = pending.Data,
                Canonical = canonical,
                LeafHash = leafHash,
                CreatedAt = timestamp
            };

            record.Seq = await db.InsertWithInt64IdentityAsync(record, token: cancellationToken);
            frontier.Append(leafHash);
        }

        var root = frontier.Root();
        var checkpointSeq = ledger.LastCheckpointSeq + 1;
        var checkpoint = new Checkpoint(
            AuditDb.LedgerName,
            checkpointSeq,
            frontier.Size,
            root,
            ledger.PreviousCheckpointHash,
            timestamp);

        var payload = CheckpointCodec.Encode(checkpoint);
        var signature = await store.SignAsync(payload, cancellationToken);
        var payloadHash = CheckpointCodec.HashPayload(payload);

        // Anchors first, database commit second: an entry that exists without an anchor would be untrustworthy.
        await store.PutCheckpointAsync(
            AuditDb.LedgerName,
            new AnchoredCheckpoint(checkpoint, payload, signature.Signature, signature.KeyVersion, payloadHash),
            cancellationToken);

        await store.PutHeadsAsync(
            new LedgerHeads(AuditDb.LedgerName, checkpointSeq, frontier.Size, root, payloadHash, timestamp),
            cancellationToken);

        ledger.TreeSize = frontier.Size;
        ledger.Frontier = FrontierCodec.Encode(frontier);
        ledger.LastCheckpointSeq = checkpointSeq;
        ledger.PreviousCheckpointHash = payloadHash;
        await db.UpdateAsync(ledger, token: cancellationToken);

        await db.InsertAsync(
            new AuditCheckpointRecord
            {
                Seq = checkpointSeq,
                Ledger = AuditDb.LedgerName,
                TreeSize = frontier.Size,
                Root = root,
                PreviousCheckpointHash = checkpoint.PreviousCheckpointHash,
                Payload = payload,
                Signature = signature.Signature,
                KeyVersion = signature.KeyVersion,
                PayloadHash = payloadHash,
                CreatedAt = timestamp
            },
            token: cancellationToken);

        await db.GetTable<AuditLogRecord>()
            .Where(r => r.Ledger == AuditDb.LedgerName && r.CheckpointSeq == null)
            .Set(r => r.CheckpointSeq, checkpointSeq)
            .UpdateAsync(cancellationToken);

        return checkpointSeq;
    }

    private static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % 10, TimeSpan.Zero);
    }
}

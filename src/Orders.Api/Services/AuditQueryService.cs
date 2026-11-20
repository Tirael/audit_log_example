using System.Text;
using AuditLog;
using AuditLog.Anchoring;
using AuditLog.Merkle;
using LinqToDB;
using LinqToDB.Async;
using Orders.Api.Data;

namespace Orders.Api.Services;

public sealed record AuditEntryDto(
    long Seq,
    long LeafIndex,
    Guid Id,
    string Actor,
    string Action,
    string EntityType,
    Guid EntityId,
    string? FromStatus,
    string? ToStatus,
    string Data,
    string LeafHash,
    DateTimeOffset CreatedAt,
    long? CheckpointSeq);

public sealed record InclusionProofDto(
    long LeafIndex,
    long TreeSize,
    string Root,
    string LeafHash,
    IReadOnlyList<string> AuditPath);

public sealed record ConsistencyProofDto(
    long First,
    long Second,
    string FirstRoot,
    string SecondRoot,
    IReadOnlyList<string> Proof);

public sealed record CheckpointDto(
    long Seq,
    long TreeSize,
    string Root,
    string? PreviousCheckpointHash,
    string PayloadHash,
    string Payload,
    string Signature,
    int KeyVersion,
    DateTimeOffset CreatedAt);

public sealed record HeadsDto(long Seq, long TreeSize, string Root, string CheckpointHash, DateTimeOffset UpdatedAt);

public sealed record JournalExportDto(
    string Ledger,
    IReadOnlyList<AuditEntryDto> Entries,
    IReadOnlyList<CheckpointDto> Checkpoints,
    string PublicKeyPem,
    int PublicKeyVersion,
    HeadsDto? Heads);

/// <summary>Read-side queries over the journal: entries, Merkle proofs, checkpoints and an offline-verifiable export.</summary>
public sealed class AuditQueryService(AuditDbFactory dbFactory, ICheckpointStore store)
{
    public async Task<IReadOnlyList<AuditEntryDto>> ListEntriesAsync(long afterLeafIndex, int limit, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        var rows = await db.GetTable<AuditLogRecord>()
            .Where(r => r.Ledger == AuditDb.LedgerName && r.LeafIndex > afterLeafIndex)
            .OrderBy(r => r.LeafIndex)
            .Take(Math.Clamp(limit, 1, 1000))
            .ToListAsync(cancellationToken);

        return rows.Select(ToDto).ToList();
    }

    public async Task<InclusionProofDto> GetInclusionProofAsync(long leafIndex, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        var checkpoint = await GetLatestCheckpointAsync(db, cancellationToken)
            ?? throw new InvalidOperationException("The journal has no checkpoints yet.");

        if (leafIndex < 0 || leafIndex >= checkpoint.TreeSize)
            throw new BadHttpRequestException($"Leaf index must be between 0 and {checkpoint.TreeSize - 1}.");

        var leaves = await LoadLeafHashesAsync(db, checkpoint.TreeSize, cancellationToken);
        var auditPath = MerkleTree.BuildInclusionProof(leaves, (int)leafIndex);

        return new InclusionProofDto(
            leafIndex,
            checkpoint.TreeSize,
            Hex.Encode(checkpoint.Root),
            Hex.Encode(leaves[(int)leafIndex]),
            auditPath.Select(h => Hex.Encode(h)).ToList());
    }

    public async Task<ConsistencyProofDto> GetConsistencyProofAsync(long first, long second, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        var checkpoints = await db.GetTable<AuditCheckpointRecord>()
            .Where(c => c.Ledger == AuditDb.LedgerName && (c.Seq == first || c.Seq == second || c.TreeSize == first || c.TreeSize == second))
            .OrderBy(c => c.Seq)
            .ToListAsync(cancellationToken);

        var firstCheckpoint = checkpoints.FirstOrDefault(c => c.TreeSize == first)
            ?? throw new BadHttpRequestException($"Tree size {first} is not anchored.");
        var secondCheckpoint = checkpoints.FirstOrDefault(c => c.TreeSize == second && c.TreeSize > first)
            ?? throw new BadHttpRequestException($"Tree size {second} is not anchored after size {first}.");

        var leaves = await LoadLeafHashesAsync(db, secondCheckpoint.TreeSize, cancellationToken);
        var proof = MerkleTree.BuildConsistencyProof(leaves, (int)first, (int)second);

        return new ConsistencyProofDto(
            first,
            second,
            Hex.Encode(firstCheckpoint.Root),
            Hex.Encode(secondCheckpoint.Root),
            proof.Select(h => Hex.Encode(h)).ToList());
    }

    public async Task<IReadOnlyList<CheckpointDto>> ListCheckpointsAsync(CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        var rows = await db.GetTable<AuditCheckpointRecord>()
            .Where(c => c.Ledger == AuditDb.LedgerName)
            .OrderBy(c => c.Seq)
            .ToListAsync(cancellationToken);

        return rows.Select(ToDto).ToList();
    }

    public async Task<JournalExportDto> ExportAsync(long fromLeafIndex, long? toLeafIndex, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        var rows = await db.GetTable<AuditLogRecord>()
            .Where(r => r.Ledger == AuditDb.LedgerName && r.LeafIndex >= fromLeafIndex && (toLeafIndex == null || r.LeafIndex <= toLeafIndex))
            .OrderBy(r => r.LeafIndex)
            .ToListAsync(cancellationToken);

        var checkpoints = await ListCheckpointsAsync(cancellationToken);
        var publicKey = await store.ReadPublicKeyAsync(null, cancellationToken);
        var heads = await store.ReadHeadsAsync(AuditDb.LedgerName, cancellationToken);

        return new JournalExportDto(
            AuditDb.LedgerName,
            rows.Select(ToDto).ToList(),
            checkpoints,
            publicKey.Pem,
            publicKey.KeyVersion,
            heads is null ? null : new HeadsDto(heads.Seq, heads.TreeSize, Hex.Encode(heads.Root), Hex.Encode(heads.CheckpointHash), heads.UpdatedAt));
    }

    public Task<PublicSigningKey> GetPublicKeyAsync(CancellationToken cancellationToken) =>
        store.ReadPublicKeyAsync(null, cancellationToken);

    private static async Task<List<byte[]>> LoadLeafHashesAsync(
        LinqToDB.Data.DataConnection db, long treeSize, CancellationToken cancellationToken)
    {
        var hashes = await db.GetTable<AuditLogRecord>()
            .Where(r => r.Ledger == AuditDb.LedgerName && r.LeafIndex < treeSize)
            .OrderBy(r => r.LeafIndex)
            .Select(r => r.LeafHash)
            .ToListAsync(cancellationToken);

        if (hashes.Count != treeSize)
            throw new InvalidOperationException($"Expected {treeSize} leaves but found {hashes.Count}.");

        return hashes;
    }

    private static Task<AuditCheckpointRecord?> GetLatestCheckpointAsync(
        LinqToDB.Data.DataConnection db, CancellationToken cancellationToken) =>
        db.GetTable<AuditCheckpointRecord>()
            .Where(c => c.Ledger == AuditDb.LedgerName)
            .OrderByDescending(c => c.Seq)
            .FirstOrDefaultAsync(cancellationToken);

    private static AuditEntryDto ToDto(AuditLogRecord row) => new(
        row.Seq,
        row.LeafIndex,
        row.Id,
        row.Actor,
        row.Action,
        row.EntityType,
        row.EntityId,
        row.FromStatus,
        row.ToStatus,
        Encoding.UTF8.GetString(row.DataCanonical),
        Hex.Encode(row.LeafHash),
        row.CreatedAt,
        row.CheckpointSeq);

    private static CheckpointDto ToDto(AuditCheckpointRecord row) => new(
        row.Seq,
        row.TreeSize,
        Hex.Encode(row.Root),
        row.PreviousCheckpointHash is null ? null : Hex.Encode(row.PreviousCheckpointHash),
        Hex.Encode(row.PayloadHash),
        Encoding.UTF8.GetString(row.Payload),
        Convert.ToBase64String(row.Signature),
        row.KeyVersion,
        row.CreatedAt);
}

namespace AuditLog.Anchoring;

/// <summary>
/// A periodic commitment to the state of the log. Checkpoints are chained: each one carries the hash
/// of the previous checkpoint's payload, so removing or reordering anchors is detectable.
/// </summary>
public sealed record Checkpoint(
    string Ledger,
    long Seq,
    long TreeSize,
    byte[] Root,
    byte[]? PreviousCheckpointHash,
    DateTimeOffset CreatedAt)
{
    public const int CurrentSchemaVersion = 1;
}

/// <summary>A checkpoint together with its signature and the hash of the exact bytes that were signed.</summary>
public sealed record AnchoredCheckpoint(
    Checkpoint Checkpoint,
    byte[] Payload,
    byte[] Signature,
    int KeyVersion,
    byte[] PayloadHash);

/// <summary>Pointer to the newest anchored checkpoint, kept next to the checkpoints in Vault.</summary>
public sealed record LedgerHeads(
    string Ledger,
    long Seq,
    long TreeSize,
    byte[] Root,
    byte[] CheckpointHash,
    DateTimeOffset UpdatedAt);

/// <summary>Public half of the Transit key, exported so a journal can be verified without Vault.</summary>
public sealed record PublicSigningKey(string KeyName, int KeyVersion, string Pem);

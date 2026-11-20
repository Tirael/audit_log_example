namespace AuditLog.Canonical;

/// <summary>
/// Everything that is bound into an audit entry's Merkle leaf.
/// The position of the entry in the log is <em>not</em> part of the payload: the tree index binds it.
/// </summary>
public sealed record AuditEventFields(
    string Ledger,
    DateTimeOffset Timestamp,
    string Actor,
    string Action,
    string EntityType,
    string EntityId,
    string? FromStatus,
    string? ToStatus,
    ReadOnlyMemory<byte> DataHash);

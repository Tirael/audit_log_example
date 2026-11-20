namespace Orders.Api.Data;

public sealed class OrderRecord
{
    public Guid Id { get; set; }

    public string Customer { get; set; } = string.Empty;

    public decimal Amount { get; set; }

    public string Status { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class AuditLogRecord
{
    /// <summary>Surrogate key with gaps allowed (identity), used for ordering and pagination.</summary>
    public long Seq { get; set; }

    /// <summary>Dense position in the Merkle tree, 0..n-1. Assigned under the ledger lock.</summary>
    public long LeafIndex { get; set; }

    public Guid Id { get; set; }

    public string Ledger { get; set; } = string.Empty;

    public string Actor { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;

    public string EntityType { get; set; } = string.Empty;

    public Guid EntityId { get; set; }

    public string? FromStatus { get; set; }

    public string? ToStatus { get; set; }

    /// <summary>Exact payload bytes; their SHA-256 is part of the canonical entry.</summary>
    public byte[] DataCanonical { get; set; } = [];

    /// <summary>Canonical binary encoding (see <c>AuditCanonicalizer</c>) that was hashed into the leaf.</summary>
    public byte[] Canonical { get; set; } = [];

    public byte[] LeafHash { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }

    public long? CheckpointSeq { get; set; }
}

public sealed class AuditLedgerRecord
{
    public string Ledger { get; set; } = string.Empty;

    public long TreeSize { get; set; }

    /// <summary>Serialized Merkle frontier. A cache only: verification never trusts it.</summary>
    public byte[] Frontier { get; set; } = [];

    public long LastCheckpointSeq { get; set; }

    public byte[]? PreviousCheckpointHash { get; set; }
}

public sealed class AuditCheckpointRecord
{
    public long Seq { get; set; }

    public string Ledger { get; set; } = string.Empty;

    public long TreeSize { get; set; }

    public byte[] Root { get; set; } = [];

    public byte[]? PreviousCheckpointHash { get; set; }

    public byte[] Payload { get; set; } = [];

    public byte[] Signature { get; set; } = [];

    public int KeyVersion { get; set; }

    public byte[] PayloadHash { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }
}

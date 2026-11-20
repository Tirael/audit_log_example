namespace AuditLog.Vault;

/// <summary>Vault connection settings. With Vault Agent the address points at the agent's local listener and no token is needed.</summary>
public sealed class VaultOptions
{
    public const string SectionName = "Vault";

    /// <summary>Vault (or Vault Agent proxy) base address, e.g. http://127.0.0.1:8200.</summary>
    public string Address { get; set; } = "http://127.0.0.1:8200";

    /// <summary>Static token. Only used when there is no Vault Agent in front (self-hosted runs and tests).</summary>
    public string? Token { get; set; }

    /// <summary>KV v2 mount that stores checkpoints and heads.</summary>
    public string KvMountPoint { get; set; } = "secret";

    public string TransitMountPoint { get; set; } = "transit";

    /// <summary>Transit key used to sign checkpoints (ecdsa-p256).</summary>
    public string TransitKey { get; set; } = "audit-signer";

    /// <summary>Path prefix inside the KV mount, e.g. secret/data/audit-ledger/checkpoints/2026/1.</summary>
    public string BasePath { get; set; } = "audit-ledger";

    /// <summary>How long startup waits for Vault to answer before failing.</summary>
    public int StartupTimeoutSeconds { get; set; } = 30;
}

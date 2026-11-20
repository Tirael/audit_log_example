namespace AuditLog.Anchoring;

/// <summary>A signature produced by the external signer, plus the key version that produced it.</summary>
public sealed record SignatureResult(byte[] Signature, int KeyVersion);

/// <summary>
/// The trusted, out-of-database anchor store. The database may be tampered with; this store may not.
/// </summary>
public interface ICheckpointStore
{
    /// <summary>Blocks until the anchor store answers or throws <see cref="AuditLogUnavailableException"/>.</summary>
    Task WaitUntilReadyAsync(CancellationToken cancellationToken);

    Task<SignatureResult> SignAsync(byte[] payload, CancellationToken cancellationToken);

    /// <summary>Public key for a specific Transit key version, or the latest one when <paramref name="keyVersion"/> is null.</summary>
    Task<PublicSigningKey> ReadPublicKeyAsync(int? keyVersion, CancellationToken cancellationToken);

    Task PutCheckpointAsync(string ledger, AnchoredCheckpoint checkpoint, CancellationToken cancellationToken);

    Task<AnchoredCheckpoint?> ReadCheckpointAsync(
        string ledger, long seq, DateTimeOffset createdAt, CancellationToken cancellationToken);

    Task PutHeadsAsync(LedgerHeads heads, CancellationToken cancellationToken);

    Task<LedgerHeads?> ReadHeadsAsync(string ledger, CancellationToken cancellationToken);
}

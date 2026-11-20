using System.Security.Cryptography;

namespace AuditLog.Anchoring;

/// <summary>
/// Verifies a Transit (ECDSA P-256, SHA-256) signature using only the exported public key,
/// which is what makes anchors checkable offline.
/// </summary>
public static class CheckpointSignature
{
    public static bool Verify(ReadOnlySpan<byte> payload, byte[] signature, string pemPublicKey)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pemPublicKey);
            return ecdsa.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Signs locally, mirroring what Transit does: SHA-256 over the payload, ECDSA P-256, DER signature.</summary>
    public static byte[] SignLocally(ReadOnlySpan<byte> payload, ECDsa key) =>
        key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
}

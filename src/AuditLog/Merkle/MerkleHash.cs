using System.Security.Cryptography;

namespace AuditLog.Merkle;

/// <summary>
/// RFC 6962 hashing rules: domain-separated leaves and interior nodes.
/// </summary>
public static class MerkleHash
{
    public const int HashSize = 32;

    private const byte LeafPrefix = 0x00;
    private const byte NodePrefix = 0x01;

    /// <summary>Leaf hash: SHA-256(0x00 || data).</summary>
    public static byte[] Leaf(ReadOnlySpan<byte> data)
    {
        var buffer = new byte[1 + data.Length];
        buffer[0] = LeafPrefix;
        data.CopyTo(buffer.AsSpan(1));
        return SHA256.HashData(buffer);
    }

    /// <summary>Interior node hash: SHA-256(0x01 || left || right).</summary>
    public static byte[] Node(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != HashSize || right.Length != HashSize)
            throw new ArgumentException($"Node children must be {HashSize}-byte hashes.");

        var buffer = new byte[1 + HashSize + HashSize];
        buffer[0] = NodePrefix;
        left.CopyTo(buffer.AsSpan(1));
        right.CopyTo(buffer.AsSpan(1 + HashSize));
        return SHA256.HashData(buffer);
    }

    public static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);
}

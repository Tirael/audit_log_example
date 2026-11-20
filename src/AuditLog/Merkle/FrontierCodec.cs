using System.Buffers.Binary;
using System.Text;

namespace AuditLog.Merkle;

/// <summary>
/// Binary encoding of <see cref="MerkleFrontier"/> for persistence.
/// Layout: magic "MFR1" | u32 peak count | { u32 peak size | 32-byte hash }*
/// </summary>
public static class FrontierCodec
{
    private static readonly byte[] Magic = "MFR1"u8.ToArray();

    public static byte[] Encode(MerkleFrontier frontier)
    {
        var peaks = frontier.Peaks;
        var buffer = new byte[Magic.Length + 4 + peaks.Count * (4 + MerkleHash.HashSize)];
        Magic.CopyTo(buffer, 0);
        BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(Magic.Length), peaks.Count);

        var offset = Magic.Length + 4;
        foreach (var peak in peaks)
        {
            BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(offset), peak.Size);
            peak.Hash.CopyTo(buffer, offset + 4);
            offset += 4 + MerkleHash.HashSize;
        }

        return buffer;
    }

    public static MerkleFrontier Decode(ReadOnlySpan<byte> data, long size)
    {
        if (data.Length < Magic.Length + 4 || !data[..Magic.Length].SequenceEqual(Magic))
            throw new FormatException("Not a Merkle frontier payload.");

        var count = BinaryPrimitives.ReadInt32BigEndian(data.Slice(Magic.Length, 4));
        if (count < 0 || data.Length != Magic.Length + 4 + count * (4 + MerkleHash.HashSize))
            throw new FormatException("Merkle frontier payload has an unexpected length.");

        var peaks = new List<MerkleFrontier.Peak>(count);
        var offset = Magic.Length + 4;
        for (var i = 0; i < count; i++)
        {
            var peakSize = BinaryPrimitives.ReadInt32BigEndian(data.Slice(offset, 4));
            var hash = data.Slice(offset + 4, MerkleHash.HashSize).ToArray();
            peaks.Add(new MerkleFrontier.Peak(peakSize, hash));
            offset += 4 + MerkleHash.HashSize;
        }

        return MerkleFrontier.FromPeaks(size, peaks);
    }

    public static string Describe(MerkleFrontier frontier)
    {
        var builder = new StringBuilder();
        builder.Append("T0..").Append(frontier.Size).Append(" peaks=");
        builder.Append(string.Join(",", frontier.Peaks.Select(p => p.Size.ToString())));
        return builder.ToString();
    }
}

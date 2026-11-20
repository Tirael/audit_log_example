namespace AuditLog.Merkle;

/// <summary>
/// Incremental Merkle tree state: the "frontier" of perfect subtree peaks, largest first.
/// Appending is O(log n) and the root is a left fold over the peaks (RFC 6962 tree shape),
/// so it always equals <see cref="MerkleTree.ComputeRoot(IReadOnlyList{byte[]})"/>.
/// </summary>
public sealed class MerkleFrontier
{
    private readonly List<Peak> _peaks = [];

    public MerkleFrontier()
    {
    }

    private MerkleFrontier(long size, IEnumerable<Peak> peaks)
    {
        Size = size;
        _peaks.AddRange(peaks);
    }

    /// <summary>A peak is the root of a perfect subtree; sizes are strictly decreasing powers of two.</summary>
    public readonly record struct Peak(int Size, byte[] Hash);

    public long Size { get; private set; }

    public IReadOnlyList<Peak> Peaks => _peaks;

    public static MerkleFrontier Empty => new();

    public static MerkleFrontier FromPeaks(long size, IEnumerable<Peak> peaks)
    {
        var list = peaks.ToList();
        long sum = 0;
        var previous = int.MaxValue;
        foreach (var peak in list)
        {
            if (!IsPowerOfTwo(peak.Size) || peak.Size >= previous)
                throw new ArgumentException("Peak sizes must be strictly decreasing powers of two.", nameof(peaks));
            if (peak.Hash.Length != MerkleHash.HashSize)
                throw new ArgumentException($"Peak hashes must be {MerkleHash.HashSize} bytes.", nameof(peaks));

            previous = peak.Size;
            sum += peak.Size;
        }

        if (sum != size)
            throw new ArgumentException("Peak sizes must add up to the tree size.", nameof(peaks));

        return new MerkleFrontier(size, list);
    }

    public void Append(byte[] leafHash)
    {
        if (leafHash.Length != MerkleHash.HashSize)
            throw new ArgumentException($"Leaf hashes must be {MerkleHash.HashSize} bytes.", nameof(leafHash));

        var carry = leafHash;
        var carrySize = 1;

        // Binary increment: merge with the smallest peaks while sizes collide.
        while (_peaks.Count > 0 && _peaks[^1].Size == carrySize)
        {
            var peak = _peaks[^1];
            _peaks.RemoveAt(_peaks.Count - 1);
            carry = MerkleHash.Node(peak.Hash, carry);
            carrySize *= 2;
        }

        _peaks.Add(new Peak(carrySize, carry));
        Size++;
    }

    /// <summary>Current root. Throws when the log is empty.</summary>
    public byte[] Root()
    {
        if (_peaks.Count == 0)
            throw new InvalidOperationException("An empty tree has no root.");

        var root = _peaks[^1].Hash;
        for (var i = _peaks.Count - 2; i >= 0; i--)
            root = MerkleHash.Node(_peaks[i].Hash, root);

        return root;
    }

    private static bool IsPowerOfTwo(int value) => value > 0 && (value & (value - 1)) == 0;
}

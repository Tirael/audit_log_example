namespace AuditLog.Merkle;

/// <summary>
/// Reference (non-incremental) Merkle tree implementation following RFC 6962 §2.1.
/// Used to compute roots and proofs for verification and as the naive oracle in tests.
/// </summary>
public static class MerkleTree
{
    public static byte[] ComputeRoot(IReadOnlyList<byte[]> leafHashes) =>
        ComputeRoot(leafHashes, 0, leafHashes.Count);

    public static byte[] ComputeRoot(IReadOnlyList<byte[]> leafHashes, int start, int count)
    {
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count), "An empty tree has no root.");
        if (count == 1)
            return leafHashes[start];

        var k = LargestPowerOfTwoBelow(count);
        return MerkleHash.Node(
            ComputeRoot(leafHashes, start, k),
            ComputeRoot(leafHashes, start + k, count - k));
    }

    /// <summary>Largest power of two strictly smaller than <paramref name="n"/> (n &gt;= 2).</summary>
    public static int LargestPowerOfTwoBelow(int n)
    {
        if (n < 2)
            throw new ArgumentOutOfRangeException(nameof(n), "n must be at least 2.");

        var k = 1;
        while ((long)k * 2 < n)
            k <<= 1;
        return k;
    }

    /// <summary>Audit path for <paramref name="index"/>, ordered from the leaf towards the root.</summary>
    public static IReadOnlyList<byte[]> BuildInclusionProof(IReadOnlyList<byte[]> leafHashes, int index)
    {
        if (leafHashes.Count == 0)
            throw new ArgumentException("An empty tree has no inclusion proofs.", nameof(leafHashes));
        if (index < 0 || index >= leafHashes.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        var path = new List<byte[]>();
        AddAuditPath(leafHashes, 0, leafHashes.Count, index, path);
        return path;
    }

    private static void AddAuditPath(
        IReadOnlyList<byte[]> leaves, int start, int count, int index, List<byte[]> path)
    {
        if (count == 1)
            return;

        var k = LargestPowerOfTwoBelow(count);
        if (index < k)
        {
            AddAuditPath(leaves, start, k, index, path);
            path.Add(ComputeRoot(leaves, start + k, count - k));
        }
        else
        {
            AddAuditPath(leaves, start + k, count - k, index - k, path);
            path.Add(ComputeRoot(leaves, start, k));
        }
    }

    /// <summary>Verifies an inclusion proof (RFC 6962 §2.1.1, as implemented by Certificate Transparency verifiers).</summary>
    public static bool VerifyInclusion(
        ReadOnlySpan<byte> leafHash,
        long index,
        long treeSize,
        IReadOnlyList<byte[]> auditPath,
        ReadOnlySpan<byte> root)
    {
        if (index < 0 || treeSize <= 0 || index >= treeSize)
            return false;

        long node = index;
        long lastNode = treeSize - 1;
        var hash = leafHash.ToArray();
        var buffer = new byte[MerkleHash.HashSize];

        foreach (var sibling in auditPath)
        {
            hash.CopyTo(buffer, 0);
            if ((node & 1) == 1 || node == lastNode)
            {
                hash = MerkleHash.Node(sibling, buffer);
                while ((node & 1) == 0 && node != 0)
                {
                    node >>= 1;
                    lastNode >>= 1;
                }
            }
            else
            {
                hash = MerkleHash.Node(buffer, sibling);
            }

            node >>= 1;
            lastNode >>= 1;
        }

        return lastNode == 0 && hash.AsSpan().SequenceEqual(root);
    }

    /// <summary>Consistency proof between tree sizes <paramref name="first"/> and <paramref name="second"/> (RFC 6962 §2.1.2).</summary>
    public static IReadOnlyList<byte[]> BuildConsistencyProof(
        IReadOnlyList<byte[]> leafHashes, int first, int second)
    {
        if (first < 0 || second < first || second > leafHashes.Count)
            throw new ArgumentOutOfRangeException(nameof(first), "Expected 0 <= first <= second <= leaf count.");

        if (first == 0 || first == second)
            return [];

        var proof = new List<byte[]>();
        Subproof(leafHashes, 0, second, first, complete: true, proof);
        return proof;
    }

    private static void Subproof(
        IReadOnlyList<byte[]> leaves, int start, int n, int m, bool complete, List<byte[]> proof)
    {
        if (m == n)
        {
            if (!complete)
                proof.Add(ComputeRoot(leaves, start, n));
            return;
        }

        var k = LargestPowerOfTwoBelow(n);
        if (m <= k)
        {
            Subproof(leaves, start, k, m, complete, proof);
            proof.Add(ComputeRoot(leaves, start + k, n - k));
        }
        else
        {
            Subproof(leaves, start + k, n - k, m - k, complete: false, proof);
            proof.Add(ComputeRoot(leaves, start, k));
        }
    }

    /// <summary>Verifies that the tree of size <paramref name="second"/> extends the tree of size <paramref name="first"/>.</summary>
    public static bool VerifyConsistency(
        long first,
        long second,
        ReadOnlySpan<byte> firstRoot,
        ReadOnlySpan<byte> secondRoot,
        IReadOnlyList<byte[]> proof)
    {
        if (first < 0 || second < first || second > int.MaxValue)
            return false;

        if (first == second)
            return proof.Count == 0 && firstRoot.SequenceEqual(secondRoot);

        // An empty first tree is consistent with every tree, and has an empty proof.
        if (first == 0)
            return proof.Count == 0;

        var cursor = 0;
        var rootM = firstRoot.ToArray();
        (byte[] Older, byte[] Newer) reconstructed;
        try
        {
            reconstructed = WalkConsistency(checked((int)second), checked((int)first), complete: true, rootM, proof, ref cursor);
        }
        catch (Exception exception) when (exception is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return false;
        }

        return cursor == proof.Count
            && reconstructed.Older.AsSpan().SequenceEqual(firstRoot)
            && reconstructed.Newer.AsSpan().SequenceEqual(secondRoot);
    }

    /// <summary>
    /// Mirrors <see cref="Subproof"/> exactly, replaying the proof from left to right:
    /// each recursion returns the reconstructed root of the older tree and of the newer tree.
    /// </summary>
    private static (byte[] Older, byte[] Newer) WalkConsistency(
        int n, int m, bool complete, byte[] olderRoot, IReadOnlyList<byte[]> proof, ref int cursor)
    {
        if (m == n)
        {
            if (complete)
                return (olderRoot, olderRoot);

            var subtree = Next(proof, ref cursor);
            return (subtree, subtree);
        }

        var k = LargestPowerOfTwoBelow(n);
        if (m <= k)
        {
            var (olderLeft, newerLeft) = WalkConsistency(k, m, complete, olderRoot, proof, ref cursor);
            var newerRight = Next(proof, ref cursor);
            return (olderLeft, MerkleHash.Node(newerLeft, newerRight));
        }
        else
        {
            var (olderRight, newerRight) = WalkConsistency(n - k, m - k, complete: false, olderRoot, proof, ref cursor);
            var olderLeft = Next(proof, ref cursor);
            return (MerkleHash.Node(olderLeft, olderRight), MerkleHash.Node(olderLeft, newerRight));
        }
    }

    private static byte[] Next(IReadOnlyList<byte[]> proof, ref int cursor) => proof[cursor++];
}

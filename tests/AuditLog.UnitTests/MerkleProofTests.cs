using AuditLog.Merkle;

namespace AuditLog.UnitTests;

public class MerkleProofTests
{
    public static TheoryData<int> TreeSizes =>
        new(Enumerable.Range(1, 40).Select(i => i).Concat([64, 65, 100]).ToArray());

    [Theory]
    [MemberData(nameof(TreeSizes))]
    public void EveryInclusionProofVerifies(int treeSize)
    {
        var random = new Random(treeSize);
        var leaves = Enumerable.Range(0, treeSize).Select(_ => MerkleFrontierTests.RandomLeaf(random)).ToList();
        var root = MerkleTree.ComputeRoot(leaves);

        for (var index = 0; index < treeSize; index++)
        {
            var proof = MerkleTree.BuildInclusionProof(leaves, index);
            MerkleTree.VerifyInclusion(leaves[index], index, treeSize, proof, root)
                .Should().BeTrue($"leaf {index} of {treeSize} must be provable");
        }
    }

    [Theory]
    [MemberData(nameof(TreeSizes))]
    public void InclusionProofRejectsTamperedInputs(int treeSize)
    {
        var random = new Random(treeSize * 31);
        var leaves = Enumerable.Range(0, treeSize).Select(_ => MerkleFrontierTests.RandomLeaf(random)).ToList();
        var root = MerkleTree.ComputeRoot(leaves);
        var index = treeSize / 2;
        var proof = MerkleTree.BuildInclusionProof(leaves, index).ToList();

        var wrongLeaf = MerkleHash.Leaf("tampered"u8);
        MerkleTree.VerifyInclusion(wrongLeaf, index, treeSize, proof, root).Should().BeFalse();

        if (proof.Count > 0)
        {
            var brokenProof = proof.ToList();
            brokenProof[0] = MerkleHash.Leaf("broken"u8);
            MerkleTree.VerifyInclusion(leaves[index], index, treeSize, brokenProof, root).Should().BeFalse();
        }

        var wrongRoot = MerkleHash.Leaf("other root"u8);
        MerkleTree.VerifyInclusion(leaves[index], index, treeSize, proof, wrongRoot).Should().BeFalse();

        if (treeSize > 1)
        {
            var otherIndex = (index + 1) % treeSize;
            MerkleTree.VerifyInclusion(leaves[otherIndex], index, treeSize, proof, root).Should().BeFalse();
        }
    }

    [Fact]
    public void EveryConsistencyProofVerifies()
    {
        var random = new Random(99);
        var leaves = Enumerable.Range(0, 48).Select(_ => MerkleFrontierTests.RandomLeaf(random)).ToList();

        for (var second = 1; second <= leaves.Count; second++)
        {
            var secondRoot = MerkleTree.ComputeRoot(leaves.Take(second).ToList());
            for (var first = 1; first <= second; first++)
            {
                var firstRoot = MerkleTree.ComputeRoot(leaves.Take(first).ToList());
                var proof = MerkleTree.BuildConsistencyProof(leaves, first, second);

                MerkleTree.VerifyConsistency(first, second, firstRoot, secondRoot, proof)
                    .Should().BeTrue($"{first} -> {second} must be consistent");
            }
        }
    }

    [Fact]
    public void ConsistencyProofRejectsTamperedInputs()
    {
        var random = new Random(123);
        var leaves = Enumerable.Range(0, 20).Select(_ => MerkleFrontierTests.RandomLeaf(random)).ToList();
        const int first = 7;
        const int second = 20;

        var firstRoot = MerkleTree.ComputeRoot(leaves.Take(first).ToList());
        var secondRoot = MerkleTree.ComputeRoot(leaves);
        var proof = MerkleTree.BuildConsistencyProof(leaves, first, second).ToList();

        MerkleTree.VerifyConsistency(first, second, firstRoot, secondRoot, proof).Should().BeTrue();

        var truncated = proof.Take(proof.Count - 1).ToList();
        MerkleTree.VerifyConsistency(first, second, firstRoot, secondRoot, truncated).Should().BeFalse();

        var forgedFirstRoot = MerkleTree.ComputeRoot(leaves.Take(first - 1).ToList());
        MerkleTree.VerifyConsistency(first, second, forgedFirstRoot, secondRoot, proof).Should().BeFalse();

        var reordered = proof.ToList();
        reordered.Reverse();
        MerkleTree.VerifyConsistency(first, second, firstRoot, secondRoot, reordered).Should().BeFalse();
    }

    [Fact]
    public void SameSizeIsConsistentWithEmptyProof()
    {
        var random = new Random(5);
        var leaves = Enumerable.Range(0, 10).Select(_ => MerkleFrontierTests.RandomLeaf(random)).ToList();
        var root = MerkleTree.ComputeRoot(leaves);

        MerkleTree.VerifyConsistency(10, 10, root, root, []).Should().BeTrue();
    }
}

using AuditLog.Merkle;

namespace AuditLog.UnitTests;

public class MerkleFrontierTests
{
    [Fact]
    public void IncrementalRootAlwaysMatchesRecursiveTree()
    {
        var random = new Random(20260101);
        var leaves = new List<byte[]>();
        var frontier = MerkleFrontier.Empty;

        for (var size = 0; size < 257; size++)
        {
            var leaf = RandomLeaf(random);
            leaves.Add(leaf);
            frontier.Append(leaf);

            frontier.Size.Should().Be(leaves.Count);
            frontier.Root().Should().Equal(MerkleTree.ComputeRoot(leaves));
        }
    }

    [Fact]
    public void PeaksAreDecreasingPowersOfTwo()
    {
        var random = new Random(7);
        var frontier = MerkleFrontier.Empty;
        for (var i = 0; i < 100; i++)
            frontier.Append(RandomLeaf(random));

        frontier.Peaks.Select(p => p.Size).Should().Equal(64, 32, 4);
    }

    [Fact]
    public void EmptyFrontierHasNoRoot()
    {
        var frontier = MerkleFrontier.Empty;
        var act = () => frontier.Root();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void FrontierCodecRoundTrips()
    {
        var random = new Random(42);
        var frontier = MerkleFrontier.Empty;
        for (var i = 0; i < 37; i++)
            frontier.Append(RandomLeaf(random));

        var decoded = FrontierCodec.Decode(FrontierCodec.Encode(frontier), frontier.Size);

        decoded.Size.Should().Be(frontier.Size);
        decoded.Root().Should().Equal(frontier.Root());
        decoded.Peaks.Select(p => p.Size).Should().Equal(frontier.Peaks.Select(p => p.Size));
    }

    [Fact]
    public void FrontierCodecRejectsCorruptedPayload()
    {
        var bytes = FrontierCodec.Encode(MerkleFrontier.Empty);
        bytes[0] = 0x00;

        var act = () => FrontierCodec.Decode(bytes, 0);
        act.Should().Throw<FormatException>();
    }

    internal static byte[] RandomLeaf(Random random)
    {
        var data = new byte[random.Next(1, 64)];
        random.NextBytes(data);
        return MerkleHash.Leaf(data);
    }
}

using System.Security.Cryptography;
using AuditLog.Anchoring;

namespace AuditLog.UnitTests;

public class CheckpointTests
{
    private static Checkpoint SampleCheckpoint(byte[]? previous = null) => new(
        Ledger: "orders",
        Seq: 3,
        TreeSize: 12,
        Root: Convert.FromHexString(new string('a', 64)),
        PreviousCheckpointHash: previous ?? Convert.FromHexString(new string('b', 64)),
        CreatedAt: DateTimeOffset.Parse("2026-11-20T12:34:56.1234560+00:00"));

    [Fact]
    public void PayloadEncodingIsDeterministic()
    {
        var checkpoint = SampleCheckpoint();
        CheckpointCodec.Encode(checkpoint).Should().Equal(CheckpointCodec.Encode(checkpoint));
        CheckpointCodec.Encode(checkpoint).Should().Equal(CheckpointCodec.Encode(SampleCheckpoint()));
    }

    [Fact]
    public void PayloadRoundTrips()
    {
        var checkpoint = SampleCheckpoint();
        var decoded = CheckpointCodec.Decode(CheckpointCodec.Encode(checkpoint));

        decoded.Should().BeEquivalentTo(checkpoint);
    }

    [Fact]
    public void ChainHashChangesWithPreviousCheckpoint()
    {
        var first = CheckpointCodec.HashPayload(CheckpointCodec.Encode(SampleCheckpoint()));
        var second = CheckpointCodec.HashPayload(CheckpointCodec.Encode(SampleCheckpoint(new byte[32])));

        first.Should().NotEqual(second);
    }

    [Fact]
    public void SignatureVerifiesOfflineWithExportedPublicKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var payload = CheckpointCodec.Encode(SampleCheckpoint());
        var signature = CheckpointSignature.SignLocally(payload, key);
        var pem = key.ExportSubjectPublicKeyInfoPem();

        CheckpointSignature.Verify(payload, signature, pem).Should().BeTrue();
    }

    [Fact]
    public void SignatureDoesNotVerifyForTamperedPayload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var payload = CheckpointCodec.Encode(SampleCheckpoint());
        var signature = CheckpointSignature.SignLocally(payload, key);
        var tampered = CheckpointCodec.Encode(SampleCheckpoint() with { TreeSize = 13 });

        CheckpointSignature.Verify(tampered, signature, key.ExportSubjectPublicKeyInfoPem()).Should().BeFalse();
    }

    [Fact]
    public void SignatureDoesNotVerifyForAnotherKey()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var payload = CheckpointCodec.Encode(SampleCheckpoint());
        var signature = CheckpointSignature.SignLocally(payload, signer);

        CheckpointSignature.Verify(payload, signature, other.ExportSubjectPublicKeyInfoPem()).Should().BeFalse();
    }
}

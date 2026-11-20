using AuditLog.Canonical;

namespace AuditLog.UnitTests;

public class AuditCanonicalizerTests
{
    private static AuditEventFields SampleFields() => new(
        Ledger: "orders",
        Timestamp: DateTimeOffset.Parse("2026-11-20T12:34:56.1234560+00:00"),
        Actor: "alice",
        Action: "order.status_changed",
        EntityType: "order",
        EntityId: "0193f0aa-8f2d-7cbb-9a3e-1f0d8b5f6c11",
        FromStatus: "draft",
        ToStatus: "confirmed",
        DataHash: AuditCanonicalizer.HashData("""{"customer":"acme","amount":"99.90"}"""u8));

    [Fact]
    public void CanonicalEncodingIsStable()
    {
        var canonical = AuditCanonicalizer.Canonicalize(SampleFields());

        Hex.Encode(canonical).Should().Be(GoldenHex);
    }

    [Fact]
    public void LeafHashIsDomainSeparated()
    {
        var fields = SampleFields();
        var canonical = AuditCanonicalizer.Canonicalize(fields);

        AuditCanonicalizer.LeafHash(fields).Should().Equal(AuditLog.Merkle.MerkleHash.Leaf(canonical));
        AuditCanonicalizer.LeafHash(fields).Should().NotEqual(AuditCanonicalizer.HashData(canonical));
    }

    [Theory]
    [InlineData("Ledger")]
    [InlineData("Timestamp")]
    [InlineData("Actor")]
    [InlineData("Action")]
    [InlineData("EntityType")]
    [InlineData("EntityId")]
    [InlineData("FromStatus")]
    [InlineData("ToStatus")]
    [InlineData("DataHash")]
    public void EveryFieldIsBoundIntoTheHash(string field)
    {
        var baseline = SampleFields();
        var mutated = field switch
        {
            "Ledger" => baseline with { Ledger = "returns" },
            "Timestamp" => baseline with { Timestamp = baseline.Timestamp.AddMilliseconds(1) },
            "Actor" => baseline with { Actor = "bob" },
            "Action" => baseline with { Action = "order.cancelled" },
            "EntityType" => baseline with { EntityType = "invoice" },
            "EntityId" => baseline with { EntityId = "0193f0aa-8f2d-7cbb-9a3e-1f0d8b5f6c12" },
            "FromStatus" => baseline with { FromStatus = null },
            "ToStatus" => baseline with { ToStatus = "shipped" },
            "DataHash" => baseline with { DataHash = AuditCanonicalizer.HashData("{}"u8) },
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };

        AuditCanonicalizer.LeafHash(mutated).Should().NotEqual(AuditCanonicalizer.LeafHash(baseline));
    }

    [Fact]
    public void TimestampsAreTruncatedToMicroseconds()
    {
        var a = SampleFields() with { Timestamp = DateTimeOffset.Parse("2026-11-20T12:34:56.1234567+00:00") };
        var b = SampleFields() with { Timestamp = DateTimeOffset.Parse("2026-11-20T12:34:56.1234569+00:00") };

        AuditCanonicalizer.Canonicalize(a).Should().Equal(AuditCanonicalizer.Canonicalize(b));
    }

    [Fact]
    public void SameInstantInAnotherOffsetEncodesIdentically()
    {
        var utc = SampleFields();
        var moscow = utc with { Timestamp = utc.Timestamp.ToOffset(TimeSpan.FromHours(3)) };

        AuditCanonicalizer.Canonicalize(moscow).Should().Equal(AuditCanonicalizer.Canonicalize(utc));
    }

    private const string GoldenHex = "41554c4701000000066f7264657273000660b478ba5e4000000005616c696365000000146f726465722e7374617475735f6368616e676564000000056f726465720000002430313933663061612d386632642d376362622d396133652d316630643862356636633131010000000564726166740100000009636f6e6669726d6564c0d242c1076dec6d68efa9c6823c4b4f80a63a0124241eae12f85b55b5d8e87f";
}

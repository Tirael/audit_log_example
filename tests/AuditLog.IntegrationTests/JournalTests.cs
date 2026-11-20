using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace AuditLog.IntegrationTests;

/// <summary>The demo scenario: business writes, proofs, and the five ways a dishonest DBA can try to rewrite history.</summary>
public sealed class JournalTests : AuditTestBase
{
    [Fact]
    public async Task HappyPath_ProducesAVerifiableJournal()
    {
        var order = await CreateOrderAsync();
        (await PostAsync($"/orders/{order}/confirm")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsync($"/orders/{order}/ship")).StatusCode.Should().Be(HttpStatusCode.OK);

        using var entries = await GetJsonAsync("/audit/entries");
        entries.RootElement.GetArrayLength().Should().Be(3);

        using var checkpoints = await GetJsonAsync("/audit/checkpoints");
        checkpoints.RootElement.GetArrayLength().Should().Be(3);

        var verify = await VerifyAsync();
        verify.GetProperty("ok").GetBoolean().Should().BeTrue(verify.ToString());
        verify.GetProperty("treeSize").GetInt64().Should().Be(3);
        verify.GetProperty("findings").GetArrayLength().Should().Be(0);

        using var proofDocument = await GetJsonAsync("/audit/proof/1");
        var proof = proofDocument.RootElement;
        var leafHash = Convert.FromHexString(proof.GetProperty("leafHash").GetString()!);
        var root = Convert.FromHexString(proof.GetProperty("root").GetString()!);
        var path = proof.GetProperty("auditPath").EnumerateArray()
            .Select(e => Convert.FromHexString(e.GetString()!)).ToList();

        AuditLog.Merkle.MerkleTree
            .VerifyInclusion(leafHash, 1, proof.GetProperty("treeSize").GetInt64(), path, root)
            .Should().BeTrue();

        (await PostAsync($"/orders/{order}/cancel")).StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task TamperedEntry_IsDetected()
    {
        await CreateOrderAsync();
        await ExecuteSqlAsync("UPDATE audit_log SET actor = 'mallory' WHERE leaf_index = 0");

        var verify = await VerifyAsync();

        verify.GetProperty("ok").GetBoolean().Should().BeFalse();
        verify.GetProperty("findings")[0].GetProperty("code").GetString().Should().Be("canonical_payload_mismatch");
        verify.GetProperty("findings")[0].GetProperty("leafIndex").GetInt64().Should().Be(0);
    }

    [Fact]
    public async Task DeletedEntry_IsDetected()
    {
        var order = await CreateOrderAsync();
        await PostAsync($"/orders/{order}/confirm");
        await PostAsync($"/orders/{order}/ship");

        await ExecuteSqlAsync("DELETE FROM audit_log WHERE leaf_index = 1");

        var verify = await VerifyAsync();

        verify.GetProperty("ok").GetBoolean().Should().BeFalse();
        verify.GetProperty("findings")[0].GetProperty("code").GetString().Should().Be("leaf_index_gap");
        verify.GetProperty("findings")[0].GetProperty("leafIndex").GetInt64().Should().Be(1);
    }

    [Fact]
    public async Task InsertedEntry_IsDetected()
    {
        await CreateOrderAsync();

        // A forged entry with self-consistent canonical bytes and hashes still changes the tree,
        // so the anchored root is what catches it.
        var timestamp = DateTimeOffset.Parse("2026-11-20T00:00:00+00:00");
        var fields = new AuditLog.Canonical.AuditEventFields(
            "orders", timestamp, "mallory", "order.created", "order",
            "0193f0aa-8f2d-7cbb-9a3e-1f0d8b5f6c11", null, "draft",
            AuditLog.Canonical.AuditCanonicalizer.HashData("{}"u8));
        var canonical = AuditLog.Canonical.AuditCanonicalizer.Canonicalize(fields);
        var leaf = AuditLog.Merkle.MerkleHash.Leaf(canonical);

        await ExecuteSqlAsync($"""
            INSERT INTO audit_log (leaf_index, ledger, actor, action, entity_type, entity_id, from_status, to_status,
                                   data_canonical, canonical, leaf_hash, created_at, checkpoint_seq)
            VALUES (1, 'orders', 'mallory', 'order.created', 'order',
                    '0193f0aa-8f2d-7cbb-9a3e-1f0d8b5f6c11', NULL, 'draft',
                    decode('{Convert.ToHexStringLower("{}"u8)}', 'hex'),
                    decode('{AuditLog.Hex.Encode(canonical)}', 'hex'),
                    decode('{AuditLog.Hex.Encode(leaf)}', 'hex'),
                    '2026-11-20T00:00:00Z', 1)
            """);

        var verify = await VerifyAsync();

        verify.GetProperty("ok").GetBoolean().Should().BeFalse();
        verify.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("code").GetString())
            .Should().Contain("unanchored_entries");
    }

    [Fact]
    public async Task DatabaseRolledBackBehindItsAnchors_IsDetected()
    {
        var order = await CreateOrderAsync();
        await PostAsync($"/orders/{order}/confirm");

        // Restore an "older backup": only the first checkpoint survives, Vault still knows the newest.
        await ExecuteSqlAsync("""
            DELETE FROM audit_log WHERE leaf_index >= 1;
            DELETE FROM audit_checkpoints WHERE seq >= 2;
            UPDATE audit_ledger
               SET tree_size = 1,
                   last_checkpoint_seq = 1
             WHERE ledger = 'orders';
            """);

        var verify = await VerifyAsync();

        verify.GetProperty("ok").GetBoolean().Should().BeFalse();
        verify.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("code").GetString())
            .Should().Contain("database_rolled_back");
    }

    [Fact]
    public async Task TamperedFrontierCache_DoesNotAffectVerification()
    {
        var order = await CreateOrderAsync();
        await PostAsync($"/orders/{order}/confirm");

        // The frontier is a cache; verification must not trust it.
        await ExecuteSqlAsync("""
            UPDATE audit_ledger
               SET frontier = decode('00', 'hex'), tree_size = 999
             WHERE ledger = 'orders';
            """);

        var verify = await VerifyAsync();
        verify.GetProperty("ok").GetBoolean().Should().BeTrue(verify.ToString());
    }

    [Fact]
    public async Task TamperedCheckpointRow_IsDetected()
    {
        await CreateOrderAsync();
        await ExecuteSqlAsync("UPDATE audit_checkpoints SET signature = decode(repeat('00', 70), 'hex') WHERE seq = 1");

        var verify = await VerifyAsync();

        verify.GetProperty("ok").GetBoolean().Should().BeFalse();
        verify.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("code").GetString())
            .Should().Contain("checkpoint_signature_mismatch");
        verify.GetProperty("findings").EnumerateArray()
            .Select(f => f.GetProperty("code").GetString())
            .Should().Contain("checkpoint_signature_invalid");
    }

    [Fact]
    public async Task ExportContainsEverythingNeededForOfflineVerification()
    {
        var order = await CreateOrderAsync();
        await PostAsync($"/orders/{order}/confirm");

        using var export = await GetJsonAsync("/audit/export");

        export.RootElement.GetProperty("entries").GetArrayLength().Should().Be(2);
        export.RootElement.GetProperty("checkpoints").GetArrayLength().Should().Be(2);
        export.RootElement.GetProperty("publicKeyPem").GetString().Should().Contain("BEGIN PUBLIC KEY");
        export.RootElement.GetProperty("heads").GetProperty("treeSize").GetInt64().Should().Be(2);

        var checkpoint = export.RootElement.GetProperty("checkpoints")[0];
        var payload = System.Text.Encoding.UTF8.GetBytes(checkpoint.GetProperty("payload").GetString()!);
        var signature = Convert.FromBase64String(checkpoint.GetProperty("signature").GetString()!);

        AuditLog.Anchoring.CheckpointSignature
            .Verify(payload, signature, export.RootElement.GetProperty("publicKeyPem").GetString()!)
            .Should().BeTrue();
    }

    [Fact]
    public async Task MissingOrderReturnsProblemDetails()
    {
        var response = await PostAsync($"/orders/{Guid.CreateVersion7()}/confirm");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
    }

    [Fact]
    public async Task ConcurrentOrdersAreSerialisedAndAllAnchored()
    {
        var ids = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => CreateOrderAsync($"acme-{i}", 10m + i)));

        ids.Should().OnlyHaveUniqueItems();

        var verify = await VerifyAsync();
        verify.GetProperty("ok").GetBoolean().Should().BeTrue(verify.ToString());
        verify.GetProperty("treeSize").GetInt64().Should().Be(8);

        using var entries = await GetJsonAsync("/audit/entries");
        entries.RootElement.EnumerateArray()
            .Select(e => e.GetProperty("leafIndex").GetInt64())
            .Should().Equal(Enumerable.Range(0, 8).Select(i => (long)i));
    }

    [Fact]
    public async Task JsonBody_IsStoredVerbatimInTheEntry()
    {
        var order = await CreateOrderAsync("globex", 15.50m);

        using var entries = await GetJsonAsync("/audit/entries");
        var entry = entries.RootElement[0];
        entry.GetProperty("entityId").GetGuid().Should().Be(order);
        entry.GetProperty("action").GetString().Should().Be("order.created");
        entry.GetProperty("data").GetString().Should().Be("""{"customer":"globex","amount":"15.50"}""");
        entry.GetProperty("leafHash").GetString().Should().HaveLength(64);
    }

    [Fact]
    public async Task UnknownRouteReturns404()
    {
        (await Client.GetAsync("/nope")).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}

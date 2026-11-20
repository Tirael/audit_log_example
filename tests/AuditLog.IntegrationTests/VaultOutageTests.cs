using System.Net;

namespace AuditLog.IntegrationTests;

/// <summary>Losing Vault must lose the write, not silently produce unanchored audit rows.</summary>
public sealed class VaultOutageTests : AuditTestBase
{
    [Fact]
    public async Task VaultOutageRejectsTheOrderAndRollsBackTheDatabase()
    {
        await CreateOrderAsync();
        var ordersBefore = await ScalarAsync("SELECT count(*) FROM orders");
        var entriesBefore = await ScalarAsync("SELECT count(*) FROM audit_log");

        await Vault.StopAsync();

        var response = await PostAsync("/orders", new { customer = "acme", amount = 5m });

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        (await ScalarAsync("SELECT count(*) FROM orders")).Should().Be(ordersBefore);
        (await ScalarAsync("SELECT count(*) FROM audit_log")).Should().Be(entriesBefore);
    }

    [Fact]
    public async Task FailedWriteDoesNotAdvanceTheLedger()
    {
        await CreateOrderAsync();
        var ledgerBefore = await ScalarAsync("SELECT last_checkpoint_seq FROM audit_ledger WHERE ledger = 'orders'");

        await Vault.StopAsync();
        await PostAsync("/orders", new { customer = "acme", amount = 5m });

        (await ScalarAsync("SELECT last_checkpoint_seq FROM audit_ledger WHERE ledger = 'orders'"))
            .Should().Be(ledgerBefore);
    }
}

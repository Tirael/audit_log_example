using System.Net.Http.Json;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Testcontainers.PostgreSql;

namespace AuditLog.IntegrationTests;

/// <summary>
/// Spins up a real PostgreSQL 18 and a real Vault (dev mode) for every test, then hosts the API
/// in-process against them. Nothing is faked: the anchors really are written to Vault.
/// </summary>
public abstract class AuditTestBase : IAsyncLifetime
{
    private PostgreSqlContainer _postgres = null!;
    private IContainer _vault = null!;
    private WebApplicationFactory<Program> _factory = null!;

    protected HttpClient Client { get; private set; } = null!;

    protected IContainer Vault => _vault;

    public async ValueTask InitializeAsync()
    {
        _postgres = new PostgreSqlBuilder("postgres:18").Build();
        await _postgres.StartAsync();

        _vault = new ContainerBuilder("hashicorp/vault:1.20")
            .WithPortBinding(8200, assignRandomHostPort: true)
            .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .WithCommand("server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200")
            .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(request => request.ForPort(8200).ForPath("/v1/sys/health")))
            .Build();
        await _vault.StartAsync();

        await EnableTransitAsync();

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:Postgres", _postgres.GetConnectionString());
            builder.UseSetting("Vault:Address", VaultAddress);
            builder.UseSetting("Vault:Token", "root");
            builder.UseSetting("Vault:StartupTimeoutSeconds", "60");
        });

        Client = _factory.CreateClient();
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _factory.DisposeAsync();
        await _vault.DisposeAsync();
        await _postgres.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    protected string VaultAddress => $"http://{_vault.Hostname}:{_vault.GetMappedPublicPort(8200)}";

    /// <summary>Enables the transit engine and creates the signing key, as the compose bootstrap does.</summary>
    protected async Task EnableTransitAsync()
    {
        var result = await _vault.ExecAsync(
        [
            "sh", "-c",
            "export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root; " +
            "vault secrets enable transit && vault write -f transit/keys/audit-signer type=ecdsa-p256"
        ]);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Vault bootstrap failed: {result.Stderr}");
    }

    protected async Task ExecuteSqlAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    protected async Task<long> ScalarAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    protected async Task<JsonDocument> GetJsonAsync(string path)
    {
        var response = await Client.GetAsync(path);
        response.IsSuccessStatusCode.Should().BeTrue($"GET {path} returned {(int)response.StatusCode}");
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    protected async Task<HttpResponseMessage> PostAsync(string path, object? body = null, string actor = "alice")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body ?? new { }) };
        request.Headers.Add("X-Actor", actor);
        return await Client.SendAsync(request);
    }

    protected async Task<Guid> CreateOrderAsync(string customer = "acme", decimal amount = 99.90m)
    {
        var response = await PostAsync("/orders", new { customer, amount });
        response.StatusCode.Should().Be(System.Net.HttpStatusCode.Created);
        var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    protected async Task<JsonElement> VerifyAsync()
    {
        using var document = await GetJsonAsync("/audit/verify");
        return document.RootElement.Clone();
    }
}

using AuditLog;
using AuditLog.Anchoring;
using AuditLog.Vault;
using Microsoft.Extensions.Options;
using Orders.Api.Data;
using Orders.Api.Data.Migrations;
using Orders.Api.Endpoints;
using Orders.Api.Infrastructure;
using Orders.Api.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<VaultOptions>(builder.Configuration.GetSection(VaultOptions.SectionName));
builder.Services.AddSingleton(sp => sp.GetRequiredService<IOptions<VaultOptions>>().Value);

var connectionString = builder.Configuration.GetConnectionString("Postgres")
    ?? "Host=localhost;Port=5432;Database=audit;Username=audit;Password=audit";

builder.Services.AddSingleton(AuditDb.CreateOptions(connectionString));
builder.Services.AddSingleton<AuditDbFactory>();

builder.Services.AddHttpClient<ICheckpointStore, VaultCheckpointStore>((sp, http) =>
{
    var vault = sp.GetRequiredService<VaultOptions>();
    http.BaseAddress = new Uri(vault.Address.TrimEnd('/') + "/");
    http.Timeout = TimeSpan.FromSeconds(15);
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<OrderService>();
builder.Services.AddScoped<VerificationService>();
builder.Services.AddScoped<AuditQueryService>();

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi();

var app = builder.Build();

// Fail fast: without a trusted anchor store the service must not accept a single order.
var startupLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
try
{
    await app.Services.GetRequiredService<ICheckpointStore>().WaitUntilReadyAsync(CancellationToken.None);
}
catch (AuditLogUnavailableException exception)
{
    startupLogger.LogCritical(exception, "Vault is not available; refusing to start without a trusted anchor store.");
    throw;
}

MigrationRunner.Apply(connectionString);
await AuditWriter.EnsureLedgerAsync(app.Services.GetRequiredService<AuditDbFactory>());
startupLogger.LogInformation("Schema is up to date and the audit ledger is initialised.");

app.UseExceptionHandler();
app.MapOpenApi();
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).WithTags("Ops");
app.MapOrdersEndpoints();
app.MapAuditEndpoints();

app.Run();

/// <summary>Exposed so integration tests can host the API in-process.</summary>
public partial class Program;

using Orders.Api.Services;

namespace Orders.Api.Endpoints;

public static class AuditEndpoints
{
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var audit = app.MapGroup("/audit").WithTags("Audit");

        audit.MapGet("/entries", async (long? after, int? limit, AuditQueryService service, CancellationToken ct) =>
            Results.Ok(await service.ListEntriesAsync(after ?? -1, limit ?? 100, ct)));

        audit.MapGet("/proof/{leafIndex:long}", async (long leafIndex, AuditQueryService service, CancellationToken ct) =>
            Results.Ok(await service.GetInclusionProofAsync(leafIndex, ct)));

        audit.MapGet("/consistency", async (long first, long second, AuditQueryService service, CancellationToken ct) =>
            Results.Ok(await service.GetConsistencyProofAsync(first, second, ct)));

        audit.MapGet("/checkpoints", async (AuditQueryService service, CancellationToken ct) =>
            Results.Ok(await service.ListCheckpointsAsync(ct)));

        audit.MapGet("/export", async (long? from, long? to, AuditQueryService service, CancellationToken ct) =>
            Results.Ok(await service.ExportAsync(from ?? 0, to, ct)));

        audit.MapGet("/public-key", async (AuditQueryService service, CancellationToken ct) =>
        {
            var key = await service.GetPublicKeyAsync(ct);
            return Results.Ok(new { name = key.KeyName, version = key.KeyVersion, pem = key.Pem });
        });

        audit.MapGet("/verify", async (VerificationService service, CancellationToken ct) =>
        {
            var report = await service.VerifyAsync(ct);
            return Results.Ok(report);
        });

        return app;
    }
}

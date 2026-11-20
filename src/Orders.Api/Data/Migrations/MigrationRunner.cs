using FluentMigrator.Runner;
using Microsoft.Extensions.DependencyInjection;

namespace Orders.Api.Data.Migrations;

public static class MigrationRunner
{
    /// <summary>Brings the schema up to date at startup; FluentMigrator keeps its own version table.</summary>
    public static void Apply(string connectionString)
    {
        var services = new ServiceCollection()
            .AddFluentMigratorCore()
            .ConfigureRunner(runner => runner
                .AddPostgres()
                .WithGlobalConnectionString(connectionString)
                .ScanIn(typeof(MigrationRunner).Assembly).For.Migrations())
            .BuildServiceProvider();

        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<IMigrationRunner>().MigrateUp();
    }
}

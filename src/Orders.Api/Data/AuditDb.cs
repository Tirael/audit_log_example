using LinqToDB;
using LinqToDB.Data;
using LinqToDB.DataProvider.PostgreSQL;
using LinqToDB.Mapping;

namespace Orders.Api.Data;

/// <summary>
/// linq2db wiring: attribute-free fluent mapping (records stay plain POCOs) and a PostgreSQL 18 dialect.
/// </summary>
public static class AuditDb
{
    public const string LedgerName = "orders";

    public static MappingSchema CreateMapping()
    {
        var schema = new MappingSchema();
        var builder = new FluentMappingBuilder(schema);

        builder.Entity<OrderRecord>()
            .HasTableName("orders")
            .Property(x => x.Id).HasColumnName("id").IsPrimaryKey()
            .Property(x => x.Customer).HasColumnName("customer")
            .Property(x => x.Amount).HasColumnName("amount")
            .Property(x => x.Status).HasColumnName("status")
            .Property(x => x.CreatedAt).HasColumnName("created_at")
            .Property(x => x.UpdatedAt).HasColumnName("updated_at")
            .Build();

        builder.Entity<AuditLogRecord>()
            .HasTableName("audit_log")
            .Property(x => x.Seq).HasColumnName("seq").IsPrimaryKey().IsIdentity()
            .Property(x => x.LeafIndex).HasColumnName("leaf_index")
            .Property(x => x.Id).HasColumnName("id")
            .Property(x => x.Ledger).HasColumnName("ledger")
            .Property(x => x.Actor).HasColumnName("actor")
            .Property(x => x.Action).HasColumnName("action")
            .Property(x => x.EntityType).HasColumnName("entity_type")
            .Property(x => x.EntityId).HasColumnName("entity_id")
            .Property(x => x.FromStatus).HasColumnName("from_status")
            .Property(x => x.ToStatus).HasColumnName("to_status")
            .Property(x => x.DataCanonical).HasColumnName("data_canonical")
            .Property(x => x.Canonical).HasColumnName("canonical")
            .Property(x => x.LeafHash).HasColumnName("leaf_hash")
            .Property(x => x.CreatedAt).HasColumnName("created_at")
            .Property(x => x.CheckpointSeq).HasColumnName("checkpoint_seq")
            .Build();

        builder.Entity<AuditLedgerRecord>()
            .HasTableName("audit_ledger")
            .Property(x => x.Ledger).HasColumnName("ledger").IsPrimaryKey()
            .Property(x => x.TreeSize).HasColumnName("tree_size")
            .Property(x => x.Frontier).HasColumnName("frontier")
            .Property(x => x.LastCheckpointSeq).HasColumnName("last_checkpoint_seq")
            .Property(x => x.PreviousCheckpointHash).HasColumnName("previous_checkpoint_hash")
            .Build();

        builder.Entity<AuditCheckpointRecord>()
            .HasTableName("audit_checkpoints")
            .Property(x => x.Seq).HasColumnName("seq").IsPrimaryKey()
            .Property(x => x.Ledger).HasColumnName("ledger")
            .Property(x => x.TreeSize).HasColumnName("tree_size")
            .Property(x => x.Root).HasColumnName("root")
            .Property(x => x.PreviousCheckpointHash).HasColumnName("previous_checkpoint_hash")
            .Property(x => x.Payload).HasColumnName("payload")
            .Property(x => x.Signature).HasColumnName("signature")
            .Property(x => x.KeyVersion).HasColumnName("key_version")
            .Property(x => x.PayloadHash).HasColumnName("payload_hash")
            .Property(x => x.CreatedAt).HasColumnName("created_at")
            .Build();

        builder.Build();
        return schema;
    }

    public static DataOptions CreateOptions(string connectionString) =>
        new DataOptions()
            .UsePostgreSQL(connectionString, PostgreSQLVersion.v18, options => options)
            .UseMappingSchema(CreateMapping());
}

/// <summary>Creates a short-lived <see cref="DataConnection"/> per unit of work (a connection is not thread-safe).</summary>
public sealed class AuditDbFactory(DataOptions options)
{
    public DataConnection Create() => new(options);
}

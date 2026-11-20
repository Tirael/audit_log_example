using FluentMigrator;

namespace Orders.Api.Data.Migrations;

/// <summary>
/// Initial schema. PostgreSQL 18 is used for its native uuidv7() default on identifiers.
/// </summary>
[Migration(202611200001)]
public sealed class M001_InitialSchema : Migration
{
    public override void Up()
    {
        Execute.Sql(
            """
            CREATE TABLE orders (
                id          uuid PRIMARY KEY DEFAULT uuidv7(),
                customer    text NOT NULL,
                amount      numeric(18,2) NOT NULL CHECK (amount >= 0),
                status      text NOT NULL,
                created_at  timestamptz NOT NULL,
                updated_at  timestamptz NOT NULL
            );

            CREATE TABLE audit_log (
                seq           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                leaf_index    bigint NOT NULL,
                id            uuid NOT NULL DEFAULT uuidv7(),
                ledger        text NOT NULL,
                actor         text NOT NULL,
                action        text NOT NULL,
                entity_type   text NOT NULL,
                entity_id     uuid NOT NULL,
                from_status   text,
                to_status     text,
                data_canonical bytea NOT NULL,
                canonical     bytea NOT NULL,
                leaf_hash     bytea NOT NULL,
                created_at    timestamptz NOT NULL,
                checkpoint_seq bigint
            );

            CREATE UNIQUE INDEX ux_audit_log_leaf_index ON audit_log (ledger, leaf_index);
            CREATE INDEX ix_audit_log_entity ON audit_log (entity_type, entity_id);

            CREATE TABLE audit_ledger (
                ledger                  text PRIMARY KEY,
                tree_size               bigint NOT NULL,
                frontier                bytea NOT NULL,
                last_checkpoint_seq     bigint NOT NULL,
                previous_checkpoint_hash bytea
            );

            CREATE TABLE audit_checkpoints (
                ledger                  text NOT NULL,
                seq                     bigint NOT NULL,
                tree_size               bigint NOT NULL,
                root                    bytea NOT NULL,
                previous_checkpoint_hash bytea,
                payload                 bytea NOT NULL,
                signature               bytea NOT NULL,
                key_version             integer NOT NULL,
                payload_hash            bytea NOT NULL,
                created_at              timestamptz NOT NULL,
                CONSTRAINT pk_audit_checkpoints PRIMARY KEY (ledger, seq)
            );
            """);
    }

    public override void Down()
    {
        Execute.Sql(
            """
            DROP TABLE IF EXISTS audit_checkpoints;
            DROP TABLE IF EXISTS audit_ledger;
            DROP TABLE IF EXISTS audit_log;
            DROP TABLE IF EXISTS orders;
            """);
    }
}

using System.Globalization;
using System.Text.Json;
using AuditLog.Merkle;

namespace AuditLog.Anchoring;

/// <summary>
/// Deterministic JSON encoding of a <see cref="Checkpoint"/>. The payload is the exact byte sequence
/// that Vault Transit signs and whose SHA-256 is chained into the next checkpoint, so it must never
/// depend on serializer defaults: fields are written in a fixed order with fixed formats.
/// </summary>
public static class CheckpointCodec
{
    private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";

    public static byte[] Encode(Checkpoint checkpoint)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", Checkpoint.CurrentSchemaVersion);
            writer.WriteString("ledger", checkpoint.Ledger);
            writer.WriteNumber("seq", checkpoint.Seq);
            writer.WriteNumber("tree_size", checkpoint.TreeSize);
            writer.WriteString("root", Hex.Encode(checkpoint.Root));
            if (checkpoint.PreviousCheckpointHash is null)
                writer.WriteNull("previous_checkpoint_hash");
            else
                writer.WriteString("previous_checkpoint_hash", Hex.Encode(checkpoint.PreviousCheckpointHash));
            writer.WriteString(
                "created_at",
                checkpoint.CreatedAt.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    public static Checkpoint Decode(ReadOnlySpan<byte> payload)
    {
        using var document = JsonDocument.Parse(payload.ToArray());
        var root = document.RootElement;

        var previous = root.GetProperty("previous_checkpoint_hash");
        return new Checkpoint(
            Ledger: root.GetProperty("ledger").GetString() ?? throw new FormatException("Checkpoint ledger is missing."),
            Seq: root.GetProperty("seq").GetInt64(),
            TreeSize: root.GetProperty("tree_size").GetInt64(),
            Root: Hex.Decode(root.GetProperty("root").GetString() ?? throw new FormatException("Checkpoint root is missing.")),
            PreviousCheckpointHash: previous.ValueKind == JsonValueKind.Null
                ? null
                : Hex.Decode(previous.GetString()!),
            CreatedAt: DateTimeOffset.ParseExact(
                root.GetProperty("created_at").GetString()!,
                TimestampFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));
    }

    public static byte[] HashPayload(ReadOnlySpan<byte> payload) => MerkleHash.Sha256(payload);
}

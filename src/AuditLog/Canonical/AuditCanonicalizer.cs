using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using AuditLog.Merkle;

namespace AuditLog.Canonical;

/// <summary>
/// Deterministic binary encoding of an audit entry. No JSON serializer is involved, so property
/// ordering, casing or library upgrades can never change the bytes that were hashed.
/// <para>
/// Layout (all integers big-endian):<br/>
/// "AULG" | u8 schema_version | string ledger | i64 timestamp_micros (UTC) | string actor |
/// string action | string entity_type | string entity_id | nullable string from_status |
/// nullable string to_status | 32-byte data_hash<br/>
/// string = u32 byte length | UTF-8 bytes; nullable string = u8 0, or u8 1 followed by string.
/// </para>
/// </summary>
public static class AuditCanonicalizer
{
    public const byte SchemaVersion = 1;

    private static readonly byte[] Magic = "AULG"u8.ToArray();

    public static byte[] Canonicalize(AuditEventFields fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        if (string.IsNullOrWhiteSpace(fields.Ledger))
            throw new ArgumentException("Ledger is required.", nameof(fields));
        if (fields.DataHash.Length != MerkleHash.HashSize)
            throw new ArgumentException("Data hash must be 32 bytes.", nameof(fields));

        var writer = new CanonicalWriter();
        writer.WriteBytes(Magic);
        writer.WriteByte(SchemaVersion);
        writer.WriteString(fields.Ledger);
        writer.WriteInt64(ToUnixMicroseconds(fields.Timestamp));
        writer.WriteString(fields.Actor);
        writer.WriteString(fields.Action);
        writer.WriteString(fields.EntityType);
        writer.WriteString(fields.EntityId);
        writer.WriteNullableString(fields.FromStatus);
        writer.WriteNullableString(fields.ToStatus);
        writer.WriteBytes(fields.DataHash.Span);
        return writer.ToArray();
    }

    public static byte[] LeafHash(AuditEventFields fields) => MerkleHash.Leaf(Canonicalize(fields));

    /// <summary>Hash of the free-form event payload; the payload itself is stored verbatim.</summary>
    public static byte[] HashData(ReadOnlySpan<byte> dataBytes) => SHA256.HashData(dataBytes);

    private static long ToUnixMicroseconds(DateTimeOffset timestamp) =>
        // Truncate to whole microseconds so the value survives a round-trip through PostgreSQL timestamptz.
        (timestamp.ToUniversalTime() - DateTimeOffset.UnixEpoch).Ticks / 10;

    private sealed class CanonicalWriter
    {
        private readonly ArrayBufferWriter<byte> _buffer = new();

        public void WriteByte(byte value) => _buffer.Write([value]);

        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            var destination = _buffer.GetSpan(value.Length);
            value.CopyTo(destination);
            _buffer.Advance(value.Length);
        }

        public void WriteInt64(long value)
        {
            var destination = _buffer.GetSpan(8);
            BinaryPrimitives.WriteInt64BigEndian(destination, value);
            _buffer.Advance(8);
        }

        public void WriteString(string value)
        {
            var byteCount = Encoding.UTF8.GetByteCount(value);
            var destination = _buffer.GetSpan(4 + byteCount);
            BinaryPrimitives.WriteInt32BigEndian(destination, byteCount);
            Encoding.UTF8.GetBytes(value, destination[4..]);
            _buffer.Advance(4 + byteCount);
        }

        public void WriteNullableString(string? value)
        {
            if (value is null)
            {
                WriteByte(0);
                return;
            }

            WriteByte(1);
            WriteString(value);
        }

        public byte[] ToArray() => _buffer.WrittenSpan.ToArray();
    }
}

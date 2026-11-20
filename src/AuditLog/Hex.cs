namespace AuditLog;

/// <summary>Hex helpers. All hashes leave this library as lowercase hex strings for storage and transport.</summary>
public static class Hex
{
    public static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    public static byte[] Decode(string hex) => Convert.FromHexString(hex);

    public static bool TryDecode(string hex, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}

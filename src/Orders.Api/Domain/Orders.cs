using System.Text.Json;

namespace Orders.Api.Domain;

public enum OrderStatus
{
    Draft,
    Confirmed,
    Shipped,
    Cancelled
}

public static class OrderStatusTransitions
{
    private static readonly Dictionary<OrderStatus, OrderStatus[]> Allowed = new()
    {
        [OrderStatus.Draft] = [OrderStatus.Confirmed, OrderStatus.Cancelled],
        [OrderStatus.Confirmed] = [OrderStatus.Shipped, OrderStatus.Cancelled],
        [OrderStatus.Shipped] = [],
        [OrderStatus.Cancelled] = []
    };

    public static bool IsAllowed(OrderStatus from, OrderStatus to) =>
        Allowed.TryGetValue(from, out var targets) && targets.Contains(to);

    public static string ToStorage(this OrderStatus status) => status.ToString().ToLowerInvariant();

    public static OrderStatus Parse(string value) => Enum.Parse<OrderStatus>(value, ignoreCase: true);
}

public sealed class OrderNotFoundException(Guid id) : Exception($"Order {id} was not found.");

public sealed class InvalidOrderTransitionException(Guid id, OrderStatus from, OrderStatus to)
    : Exception($"Order {id} cannot move from {from.ToStorage()} to {to.ToStorage()}.");

/// <summary>
/// Builds the free-form payload stored next to an audit entry. Written with a JSON writer in a fixed
/// order so the bytes are reproducible; only their SHA-256 is bound into the canonical entry.
/// </summary>
public static class AuditData
{
    public static byte[] Json(params (string Key, string Value)[] fields)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var (key, value) in fields)
                writer.WriteString(key, value);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}

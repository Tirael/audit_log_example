using LinqToDB;
using LinqToDB.Async;
using Orders.Api.Data;
using Orders.Api.Domain;

namespace Orders.Api.Services;

public sealed record CreateOrderRequest(string Customer, decimal Amount);

/// <summary>
/// Example domain. Every command changes the order and appends an audit entry in the same transaction,
/// and that transaction only commits after the Merkle root covering the entry is anchored in Vault.
/// </summary>
public sealed class OrderService(AuditDbFactory dbFactory, AuditWriter auditWriter, TimeProvider clock)
{
    public async Task<OrderRecord> CreateAsync(CreateOrderRequest request, string actor, CancellationToken cancellationToken)
    {
        var now = TruncateToMicroseconds(clock.GetUtcNow());
        var order = new OrderRecord
        {
            Id = Guid.CreateVersion7(),
            Customer = request.Customer,
            Amount = request.Amount,
            Status = OrderStatus.Draft.ToStorage(),
            CreatedAt = now,
            UpdatedAt = now
        };

        await using var db = dbFactory.Create();
        using var transaction = await db.BeginTransactionAsync(cancellationToken);

        await db.InsertAsync(order, token: cancellationToken);
        await auditWriter.AppendAsync(
            db,
            actor,
            [
                new PendingAuditEvent(
                    "order.created",
                    "order",
                    order.Id,
                    FromStatus: null,
                    ToStatus: order.Status,
                    Data: AuditData.Json(("customer", order.Customer), ("amount", order.Amount.ToString("0.00"))))
            ],
            cancellationToken);

        await db.CommitTransactionAsync(cancellationToken);
        return order;
    }

    public Task<OrderRecord> ConfirmAsync(Guid id, string actor, CancellationToken cancellationToken) =>
        TransitionAsync(id, OrderStatus.Confirmed, actor, cancellationToken);

    public Task<OrderRecord> ShipAsync(Guid id, string actor, CancellationToken cancellationToken) =>
        TransitionAsync(id, OrderStatus.Shipped, actor, cancellationToken);

    public Task<OrderRecord> CancelAsync(Guid id, string actor, CancellationToken cancellationToken) =>
        TransitionAsync(id, OrderStatus.Cancelled, actor, cancellationToken);

    public async Task<OrderRecord> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var db = dbFactory.Create();
        return await db.GetTable<OrderRecord>().SingleOrDefaultAsync(o => o.Id == id, cancellationToken)
            ?? throw new OrderNotFoundException(id);
    }

    public async Task<OrderRecord> TransitionAsync(
        Guid id, OrderStatus target, string actor, CancellationToken cancellationToken)    {
        await using var db = dbFactory.Create();
        using var transaction = await db.BeginTransactionAsync(cancellationToken);

        var order = await db.GetTable<OrderRecord>().SingleOrDefaultAsync(o => o.Id == id, cancellationToken)
            ?? throw new OrderNotFoundException(id);

        var current = OrderStatusTransitions.Parse(order.Status);
        if (!OrderStatusTransitions.IsAllowed(current, target))
            throw new InvalidOrderTransitionException(id, current, target);

        order.Status = target.ToStorage();
        order.UpdatedAt = TruncateToMicroseconds(clock.GetUtcNow());
        await db.UpdateAsync(order, token: cancellationToken);

        await auditWriter.AppendAsync(
            db,
            actor,
            [
                new PendingAuditEvent(
                    "order.status_changed",
                    "order",
                    order.Id,
                    FromStatus: current.ToStorage(),
                    ToStatus: order.Status,
                    Data: AuditData.Json(("customer", order.Customer), ("amount", order.Amount.ToString("0.00"))))
            ],
            cancellationToken);

        await db.CommitTransactionAsync(cancellationToken);
        return order;
    }

    private static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % 10, TimeSpan.Zero);
    }
}

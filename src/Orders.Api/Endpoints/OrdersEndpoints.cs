using Microsoft.AspNetCore.Http.HttpResults;
using Orders.Api.Data;
using Orders.Api.Domain;
using Orders.Api.Services;

namespace Orders.Api.Endpoints;

public sealed record OrderResponse(
    Guid Id,
    string Customer,
    decimal Amount,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt)
{
    public static OrderResponse From(OrderRecord order) => new(
        order.Id, order.Customer, order.Amount, order.Status, order.CreatedAt, order.UpdatedAt);
}

public static class OrdersEndpoints
{
    public static IEndpointRouteBuilder MapOrdersEndpoints(this IEndpointRouteBuilder app)
    {
        var orders = app.MapGroup("/orders").WithTags("Orders");

        orders.MapPost("/", async Task<Results<Created<OrderResponse>, ProblemHttpResult>> (
            CreateOrderRequest request,
            HttpContext context,
            OrderService service,
            CancellationToken cancellationToken) =>
        {
            if (string.IsNullOrWhiteSpace(request.Customer))
                return TypedResults.Problem("Customer is required.", statusCode: StatusCodes.Status400BadRequest);

            if (request.Amount < 0)
                return TypedResults.Problem("Amount must not be negative.", statusCode: StatusCodes.Status400BadRequest);

            var order = await service.CreateAsync(request, ActorOf(context), cancellationToken);
            return TypedResults.Created($"/orders/{order.Id}", OrderResponse.From(order));
        });

        orders.MapPost("/{id:guid}/confirm", (Guid id, HttpContext context, OrderService service, CancellationToken ct) =>
            Transition(id, OrderStatus.Confirmed, context, service, ct));

        orders.MapPost("/{id:guid}/ship", (Guid id, HttpContext context, OrderService service, CancellationToken ct) =>
            Transition(id, OrderStatus.Shipped, context, service, ct));

        orders.MapPost("/{id:guid}/cancel", (Guid id, HttpContext context, OrderService service, CancellationToken ct) =>
            Transition(id, OrderStatus.Cancelled, context, service, ct));

        orders.MapGet("/{id:guid}", async (Guid id, OrderService service, CancellationToken cancellationToken) =>
            Results.Ok(OrderResponse.From(await service.GetAsync(id, cancellationToken))));

        return app;
    }

    private static async Task<OrderResponse> Transition(
        Guid id, OrderStatus target, HttpContext context, OrderService service, CancellationToken cancellationToken) =>
        OrderResponse.From(await service.TransitionAsync(id, target, ActorOf(context), cancellationToken));

    /// <summary>Stand-in for real authentication: in production the actor comes from the token's subject.</summary>
    internal static string ActorOf(HttpContext context)
    {
        var value = context.Request.Headers["X-Actor"].FirstOrDefault();
        return string.IsNullOrWhiteSpace(value) ? "anonymous" : value.Trim()[..Math.Min(value.Trim().Length, 200)];
    }
}

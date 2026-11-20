using AuditLog;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Orders.Api.Domain;

namespace Orders.Api.Infrastructure;

/// <summary>Maps domain failures onto RFC 9457 problem details.</summary>
public sealed class ApiExceptionHandler(ILogger<ApiExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var (status, title) = exception switch
        {
            OrderNotFoundException => (StatusCodes.Status404NotFound, "Order not found"),
            InvalidOrderTransitionException => (StatusCodes.Status409Conflict, "Invalid status transition"),
            AuditLogUnavailableException => (StatusCodes.Status503ServiceUnavailable, "Trusted anchor store unavailable"),
            _ => (StatusCodes.Status500InternalServerError, "Unexpected error")
        };

        if (status == StatusCodes.Status500InternalServerError)
            logger.LogError(exception, "Unhandled exception for {Method} {Path}", httpContext.Request.Method, httpContext.Request.Path);
        else
            logger.LogWarning(exception, "{Title} for {Method} {Path}", title, httpContext.Request.Method, httpContext.Request.Path);

        if (status == StatusCodes.Status503ServiceUnavailable)
            httpContext.Response.Headers.RetryAfter = "5";

        httpContext.Response.StatusCode = status;
        await httpContext.Response.WriteAsJsonAsync(
            new ProblemDetails
            {
                Status = status,
                Title = title,
                Detail = exception.Message,
                Instance = httpContext.Request.Path
            },
            options: null,
            contentType: "application/problem+json",
            cancellationToken: cancellationToken);

        return true;
    }
}

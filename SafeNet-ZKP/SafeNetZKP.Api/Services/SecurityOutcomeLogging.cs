using Microsoft.AspNetCore.Mvc.Controllers;

namespace SafeNetZKP.Api.Services;

internal sealed class SecurityOutcomeLogging(RequestDelegate next, ILogger<SecurityOutcomeLogging> logger)
{
    internal static readonly object NetworkState = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var action = context.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>();
        if (action?.ControllerName is "WebAuthnEnrollment" or "WebAuthnRegistration" or
            "WebAuthnAuthentication" or "Auth" or "GatewayObservations" or "CaptivePortal")
        {
            context.Response.OnCompleted(() =>
            {
                logger.LogInformation(
                    "Resultado de segurança {Controller}.{Action} HTTP {StatusCode} estado {NetworkState} trace {TraceId}",
                    action.ControllerName, action.ActionName, context.Response.StatusCode,
                    context.Items[NetworkState], context.TraceIdentifier);
                return Task.CompletedTask;
            });
        }

        await next(context);
    }
}

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeNetZKP.Application.Services;

namespace SafeNetZKP.Api.Security;

public static class SafeNetCookieAuthentication
{
    public const string SessionIdKey = "safenet.session";

    public static void Configure(CookieAuthenticationOptions options)
    {
        options.Cookie.Name = "__Host-SafeNetZKP";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.Path = "/";
        options.ExpireTimeSpan = AuthenticatedSessionService.Lifetime;
        options.SlidingExpiration = false;
        options.Events.OnValidatePrincipal = ValidatePrincipalAsync;
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    }

    private static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        var httpContext = context.HttpContext;
        var cancellationToken = httpContext.RequestAborted;
        var sessionId = GetSessionId(context.Properties);
        if (sessionId is not null &&
            Guid.TryParse(context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) &&
            userId != Guid.Empty)
        {
            try
            {
                var sessions = httpContext.RequestServices.GetRequiredService<AuthenticatedSessionService>();
                if (await sessions.IsActiveAsync(sessionId, userId, cancellationToken))
                    return;
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger(typeof(SafeNetCookieAuthentication));
                logger.LogWarning("Não foi possível validar a sessão no armazenamento.");
            }
        }

        context.RejectPrincipal();
        await httpContext.SignOutAsync(context.Scheme.Name);
    }

    public static string? GetSessionId(AuthenticationProperties properties) =>
        properties.GetString(SessionIdKey) is { Length: 64 } id && id.All(Uri.IsHexDigit) ? id : null;

    // Utilizar somente com o identificador retornado pela verificação WebAuthn.
    public static ClaimsPrincipal CreatePrincipal(Guid verifiedUserId)
    {
        if (verifiedUserId == Guid.Empty)
            throw new ArgumentException("O identificador do usuário é obrigatório.", nameof(verifiedUserId));

        return new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, verifiedUserId.ToString("D"))],
            CookieAuthenticationDefaults.AuthenticationScheme));
    }
}

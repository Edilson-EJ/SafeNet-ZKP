using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SafeNetZKP.Api.Security;

public static class SafeNetCookieAuthentication
{
    public static void Configure(CookieAuthenticationOptions options)
    {
        options.Cookie.Name = "__Host-SafeNetZKP";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.Path = "/";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = false;
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

using Microsoft.AspNetCore.Antiforgery;

namespace SafeNetZKP.Api.Security;

public static class SafeNetAntiforgery
{
    public static void Configure(AntiforgeryOptions options)
    {
        options.HeaderName = "X-CSRF-TOKEN";
        options.Cookie.Name = "__Host-SafeNetZKP-CSRF";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.Path = "/";
    }
}

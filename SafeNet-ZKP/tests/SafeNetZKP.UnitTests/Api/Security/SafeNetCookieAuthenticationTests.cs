using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SafeNetZKP.Api.Security;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Security;

public class SafeNetCookieAuthenticationTests
{
    [Fact]
    public void Configuration_UsesSecureSessionCookieWithTwentyMinuteExpiry()
    {
        using var services = CreateServices();
        var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        Assert.Equal("__Host-SafeNetZKP", options.Cookie.Name);
        Assert.True(options.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.Strict, options.Cookie.SameSite);
        Assert.Equal("/", options.Cookie.Path);
        Assert.Equal(TimeSpan.FromMinutes(20), options.ExpireTimeSpan);
        Assert.False(options.SlidingExpiration);
    }

    [Fact]
    public void CreatePrincipal_UsesAuthenticatedServerUserId()
    {
        var userId = Guid.NewGuid();
        var principal = SafeNetCookieAuthentication.CreatePrincipal(userId);
        Assert.True(principal.Identity!.IsAuthenticated);
        Assert.Equal(userId.ToString("D"), principal.FindFirstValue(ClaimTypes.NameIdentifier));
        var context = new HttpCurrentUserContext(new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext { User = principal }
        });
        Assert.Equal(userId, context.UserId);
        Assert.Throws<ArgumentException>(() => SafeNetCookieAuthentication.CreatePrincipal(Guid.Empty));
    }

    [Fact]
    public async Task ProtectedEndpoint_RejectsAnonymousRequestWithoutRedirect()
    {
        using var services = CreateServices();
        using var scope = services.CreateScope();
        var context = CreateContext(scope.ServiceProvider, new AuthorizeAttribute());
        await CreatePipeline(services)(context);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task AuthenticatedUser_Receives403ForMissingRequiredRoleWithoutRedirect()
    {
        using var services = CreateServices();
        var cookie = await IssueTestCookie(services);
        using var scope = services.CreateScope();
        var context = CreateContext(scope.ServiceProvider, new AuthorizeAttribute { Roles = "admin" });
        context.Request.Headers.Cookie = cookie;
        await CreatePipeline(services)(context);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task Cookie_IsNonPersistentAndAuthenticatesProtectedRequest()
    {
        using var services = CreateServices();
        var cookie = await IssueTestCookie(services);
        using var scope = services.CreateScope();
        var context = CreateContext(scope.ServiceProvider, new AuthorizeAttribute());
        context.Request.Headers.Cookie = cookie;
        await CreatePipeline(services)(context);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.True(context.User.Identity!.IsAuthenticated);
    }

    private static ServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(SafeNetCookieAuthentication.Configure);
        services.AddAuthorization();
        InMemorySessionRepository.Register(services);
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext CreateContext(IServiceProvider services, IAuthorizeData authorization)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost", 4200);
        context.Response.Body = new MemoryStream();
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask,
            new EndpointMetadataCollection(authorization), "protected-test"));
        return context;
    }

    private static RequestDelegate CreatePipeline(IServiceProvider services)
    {
        var app = new ApplicationBuilder(services);
        app.UseAuthentication();
        app.UseAuthorization();
        app.Run(context => { context.Response.StatusCode = 200; return Task.CompletedTask; });
        return app.Build();
    }

    private static async Task<string> IssueTestCookie(ServiceProvider services)
    {
        using var scope = services.CreateScope();
        var context = CreateContext(scope.ServiceProvider, new AuthorizeAttribute());
        var userId = Guid.NewGuid();
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            SafeNetCookieAuthentication.CreatePrincipal(userId),
            await InMemorySessionRepository.IssueAsync(scope.ServiceProvider, userId));
        var header = Assert.Single(context.Response.Headers.SetCookie) ?? throw new InvalidOperationException();
        Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", header, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expires=", header, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", header, StringComparison.OrdinalIgnoreCase);
        return header.Split(';')[0];
    }
}

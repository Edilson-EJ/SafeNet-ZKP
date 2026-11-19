using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using SafeNetZKP.Domain.Entities;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public class AuthControllerTests
{
    [Fact]
    public async Task Me_WithSession_ReturnsOnlyIdentityAndNameWithoutCache()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie();
        var context = await fixture.Request("me", cookie);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        var data = Assert.IsType<SessionUserResponse>(Assert.IsType<OkObjectResult>(context.Items["result"]).Value);
        Assert.Equal(fixture.User.Id, data.UserId);
        Assert.Equal(fixture.User.Name, data.Name);
        Assert.Equal(new[] { "UserId", "Name" }, typeof(SessionUserResponse).GetProperties().Select(p => p.Name));
    }

    [Theory]
    [InlineData("me")]
    [InlineData("csrf")]
    [InlineData("logout")]
    public async Task Endpoints_RequireAuthentication(string action)
    {
        using var fixture = new Fixture();
        var context = await fixture.Request(action);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task Me_WhenAccountWasRemoved_Returns401()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie();
        fixture.Repository.User = null;
        var context = await fixture.Request("me", cookie);
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task ExpiredCookie_CannotAccessSession()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie(expired: true);
        Assert.Equal(401, (await fixture.Request("me", cookie)).Response.StatusCode);
    }

    [Fact]
    public async Task Logout_RequiresMatchingAntiforgeryToken_AndDeletesBrowserCookie()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie();
        var missing = await fixture.Request("logout", cookie);
        Assert.Equal(400, missing.Response.StatusCode);
        Assert.Equal(0, missing.Response.Headers.SetCookie.Count);

        var csrf = await fixture.Request("csrf", cookie);
        Assert.Equal(200, csrf.Response.StatusCode);
        Assert.Contains("no-store", csrf.Response.Headers.CacheControl.ToString());
        var token = Assert.IsType<CsrfTokenResponse>(Assert.IsType<OkObjectResult>(csrf.Items["result"]).Value).Token;
        var antiforgeryCookieHeader = Assert.Single(csrf.Response.Headers.SetCookie)!;
        Assert.Contains("__Host-SafeNetZKP-CSRF=", antiforgeryCookieHeader);
        Assert.Contains("secure", antiforgeryCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", antiforgeryCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", antiforgeryCookieHeader, StringComparison.OrdinalIgnoreCase);
        var bothCookies = cookie + "; " + antiforgeryCookieHeader.Split(';')[0];
        var invalid = await fixture.Request("logout", bothCookies, "invalid");
        Assert.Equal(400, invalid.Response.StatusCode);
        Assert.Equal(0, invalid.Response.Headers.SetCookie.Count);

        var logout = await fixture.Request("logout", bothCookies, token);
        Assert.Equal(204, logout.Response.StatusCode);
        Assert.Contains("no-store", logout.Response.Headers.CacheControl.ToString());
        var deletion = Assert.Single(logout.Response.Headers.SetCookie)!;
        Assert.Contains("__Host-SafeNetZKP=", deletion);
        Assert.Contains("expires=Thu, 01 Jan 1970", deletion, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", deletion, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(401, (await fixture.Request("me")).Response.StatusCode);
        // Uma cópia do cookie anterior continua válida: não há revogação no servidor.
        Assert.Equal(200, (await fixture.Request("me", cookie)).Response.StatusCode);
    }

    [Fact]
    public async Task CsrfAndLogout_RejectHttp()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie();
        Assert.Equal(403, (await fixture.Request("csrf", cookie, scheme: "http")).Response.StatusCode);
        Assert.Equal(403, (await fixture.Request("logout", cookie, scheme: "http")).Response.StatusCode);
    }

    [Fact]
    public async Task Logout_RejectsTokenIssuedForDifferentUser()
    {
        using var fixture = new Fixture();
        var firstCookie = await fixture.IssueCookie();
        var csrf = await fixture.Request("csrf", firstCookie);
        var token = Assert.IsType<CsrfTokenResponse>(Assert.IsType<OkObjectResult>(csrf.Items["result"]).Value).Token;
        var csrfCookie = Assert.Single(csrf.Response.Headers.SetCookie)!.Split(';')[0];
        var otherCookie = await fixture.IssueCookie(userId: Guid.NewGuid());
        var result = await fixture.Request("logout", otherCookie + "; " + csrfCookie, token);
        Assert.Equal(400, result.Response.StatusCode);
        Assert.Equal(0, result.Response.Headers.SetCookie.Count);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ServiceProvider _services;
        public User User { get; } = new("Pessoa de teste");
        public FakeRepository Repository { get; }
        public Fixture()
        {
            Repository = new FakeRepository { User = User };
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddRouting();
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(SafeNetCookieAuthentication.Configure);
            services.AddAuthorization();
            services.AddAntiforgery(SafeNetAntiforgery.Configure);
            _services = services.BuildServiceProvider();
        }

        public async Task<string> IssueCookie(bool expired = false, Guid? userId = null)
        {
            using var scope = _services.CreateScope();
            var context = Context(scope.ServiceProvider, "GET");
            var properties = new AuthenticationProperties { IsPersistent = false };
            if (expired)
            {
                properties.IssuedUtc = DateTimeOffset.UtcNow.AddMinutes(-30);
                properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-10);
            }
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                SafeNetCookieAuthentication.CreatePrincipal(userId ?? User.Id), properties);
            return Assert.Single(context.Response.Headers.SetCookie)!.Split(';')[0];
        }

        public async Task<DefaultHttpContext> Request(string action, string? cookie = null, string? token = null, string scheme = "https")
        {
            using var scope = _services.CreateScope();
            var context = Context(scope.ServiceProvider, action == "logout" ? "POST" : "GET");
            context.Request.Scheme = scheme;
            if (cookie is not null) context.Request.Headers.Cookie = cookie;
            if (token is not null) context.Request.Headers["X-CSRF-TOKEN"] = token;
            var authorize = Assert.Single(typeof(AuthController).GetCustomAttributes(typeof(AuthorizeAttribute), true));
            context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(authorize), action));
            var builder = new ApplicationBuilder(_services);
            builder.UseAuthentication();
            builder.UseAuthorization();
            builder.Run(async ctx =>
            {
                var controller = new AuthController(
                    new HttpCurrentUserContext(new HttpContextAccessor { HttpContext = ctx }),
                    new GetUserByIdUseCase(Repository), ctx.RequestServices.GetRequiredService<IAntiforgery>())
                { ControllerContext = new ControllerContext { HttpContext = ctx } };
                var result = action switch
                {
                    "me" => await controller.Me(),
                    "csrf" => controller.Csrf(),
                    "logout" => await controller.Logout(),
                    _ => throw new InvalidOperationException()
                };
                ctx.Items["result"] = result;
                ctx.Response.StatusCode = ((IStatusCodeActionResult)result).StatusCode ?? 200;
            });
            await builder.Build()(context);
            return context;
        }

        private static DefaultHttpContext Context(IServiceProvider services, string method)
        {
            var context = new DefaultHttpContext { RequestServices = services };
            context.Request.Method = method;
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost", 4200);
            context.Response.Body = new MemoryStream();
            return context;
        }
        public void Dispose() => _services.Dispose();
    }

    private sealed class FakeRepository : IUserRepository
    {
        public User? User { get; set; }
        public Task<User?> GetByIdAsync(Guid id) => Task.FromResult(User?.Id == id ? User : null);
        public Task AddAsync(User user) => throw new NotSupportedException();
    }
}

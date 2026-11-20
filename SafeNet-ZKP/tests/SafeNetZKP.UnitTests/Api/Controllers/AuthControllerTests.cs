using System.Security.Cryptography;
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
using SafeNetZKP.Application.Services;
using SafeNetZKP.UnitTests.Api.Security;
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

    [Theory]
    [InlineData("legacy")]
    [InlineData("missing")]
    [InlineData("expired")]
    [InlineData("wrong-owner")]
    [InlineData("unavailable")]
    public async Task InvalidServerSession_IsRejectedAndCookieIsCleared(string state)
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie(sessionState: state);
        var response = await fixture.Request("me", cookie);
        Assert.Equal(401, response.Response.StatusCode);
        Assert.Contains("expires=Thu, 01 Jan 1970", Assert.Single(response.Response.Headers.SetCookie)!,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Logout_RequiresMatchingAntiforgeryToken_AndDeletesBrowserCookie()
    {
        using var fixture = new Fixture();
        var cookie = await fixture.IssueCookie();
        var independentCookie = await fixture.IssueCookie();
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
        var replay = await fixture.Request("me", cookie);
        Assert.Equal(401, replay.Response.StatusCode);
        Assert.Contains("expires=Thu, 01 Jan 1970", Assert.Single(replay.Response.Headers.SetCookie)!,
            StringComparison.OrdinalIgnoreCase);
        Assert.Equal(401, (await fixture.Request("logout", bothCookies, token)).Response.StatusCode);
        Assert.Equal(200, (await fixture.Request("me", independentCookie)).Response.StatusCode);
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
        private readonly InMemorySessionRepository _sessions;
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
            _sessions = InMemorySessionRepository.Register(services);
            _services = services.BuildServiceProvider();
        }

        public async Task<string> IssueCookie(bool expired = false, Guid? userId = null, string? sessionState = null)
        {
            using var scope = _services.CreateScope();
            var context = Context(scope.ServiceProvider, "GET");
            var ownerId = userId ?? User.Id;
            var properties = new AuthenticationProperties();
            if (sessionState is "missing" or "expired")
            {
                var id = RandomNumberGenerator.GetBytes(32);
                properties.SetString(SafeNetCookieAuthentication.SessionIdKey, Convert.ToHexString(id));
                if (sessionState == "expired")
                {
                    var now = DateTime.UtcNow;
                    await _sessions.AddAsync(new AuthenticatedSession(SHA256.HashData(id), ownerId,
                        now.AddMinutes(-21), now.AddMinutes(-1)), CancellationToken.None);
                }
            }
            else if (sessionState != "legacy")
            {
                properties = await InMemorySessionRepository.IssueAsync(scope.ServiceProvider,
                    sessionState == "wrong-owner" ? Guid.NewGuid() : ownerId);
            }
            _sessions.FailReads = sessionState == "unavailable";
            if (expired)
            {
                properties.IssuedUtc = DateTimeOffset.UtcNow.AddMinutes(-30);
                properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-10);
            }
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                SafeNetCookieAuthentication.CreatePrincipal(ownerId), properties);
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
                    new GetUserByIdUseCase(Repository), ctx.RequestServices.GetRequiredService<IAntiforgery>(),
                    ctx.RequestServices.GetRequiredService<AuthenticatedSessionService>())
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

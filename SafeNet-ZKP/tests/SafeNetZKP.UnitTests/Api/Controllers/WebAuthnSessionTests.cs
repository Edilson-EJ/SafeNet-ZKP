using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.UnitTests.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public class WebAuthnSessionTests
{
    [Fact]
    public async Task ValidAssertion_IssuesSecureSessionForVerifiedUser()
    {
        using var f = new WebAuthnAuthenticationCompletionTests.Fixture("https://localhost:4200");
        using var services = CreateServices();
        using var scope = services.CreateScope();
        var controller = CreateController(f, scope.ServiceProvider);
        var operation = f.Options.Generate();
        var result = await controller.Complete(new AuthenticationCompletionRequest
        {
            OperationId = operation.OperationId, Response = f.Response(operation.Options, counter: 1)
        }, CancellationToken.None);
        Assert.Equal(f.UserId, Assert.IsType<AuthenticationCompletionResponse>(Assert.IsType<OkObjectResult>(result).Value).UserId);
        var header = Assert.Single(controller.Response.Headers.SetCookie)!;
        Assert.Contains("__Host-SafeNetZKP=", header);
        Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", header, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expires=", header, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", header, StringComparison.OrdinalIgnoreCase);

        using var nextScope = services.CreateScope();
        var next = new DefaultHttpContext { RequestServices = nextScope.ServiceProvider };
        next.Request.Scheme = "https";
        next.Request.Host = new HostString("localhost", 4200);
        next.Request.Headers.Cookie = header.Split(';')[0];
        var auth = await next.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Assert.True(auth.Succeeded);
        Assert.False(auth.Properties!.IsPersistent);
        Assert.False(auth.Properties.AllowRefresh);
        Assert.Equal(TimeSpan.FromMinutes(20), auth.Properties.ExpiresUtc - auth.Properties.IssuedUtc);
        Assert.Single(auth.Principal!.Claims);
        Assert.Equal(f.UserId.ToString(), auth.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
        next.User = auth.Principal;
        Assert.Equal(f.UserId, new HttpCurrentUserContext(new HttpContextAccessor { HttpContext = next }).UserId);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("credential")]
    [InlineData("user")]
    [InlineData("challenge")]
    [InlineData("origin")]
    public async Task InvalidAssertion_DoesNotIssueCookie(string invalid)
    {
        using var f = new WebAuthnAuthenticationCompletionTests.Fixture("https://localhost:4200");
        using var services = CreateServices();
        using var scope = services.CreateScope();
        var controller = CreateController(f, scope.ServiceProvider);
        var operation = f.Options.Generate();
        var result = await controller.Complete(new AuthenticationCompletionRequest
        {
            OperationId = operation.OperationId, Response = f.Response(operation.Options, invalid)
        }, CancellationToken.None);
        Assert.IsType<BadRequestResult>(result);
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public async Task ExpiredAndReplayedOperations_DoNotIssueCookie()
    {
        using var f = new WebAuthnAuthenticationCompletionTests.Fixture("https://localhost:4200");
        using var services = CreateServices();
        using var scope = services.CreateScope();
        var controller = CreateController(f, scope.ServiceProvider);
        var expired = f.Options.Generate();
        f.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.IsType<BadRequestResult>(await controller.Complete(new AuthenticationCompletionRequest
        {
            OperationId = expired.OperationId, Response = f.Response(expired.Options)
        }, CancellationToken.None));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        var valid = f.Options.Generate();
        var request = new AuthenticationCompletionRequest { OperationId = valid.OperationId, Response = f.Response(valid.Options) };
        Assert.IsType<OkObjectResult>(await controller.Complete(request, CancellationToken.None));
        controller.Response.Headers.Remove("Set-Cookie");
        Assert.IsType<BadRequestResult>(await controller.Complete(request, CancellationToken.None));
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
    }

    [Theory]
    [InlineData("http", "http://localhost:4200")]
    [InlineData("https", "https://evil.example")]
    [InlineData("https", "")]
    [InlineData("https", "null")]
    [InlineData("https", "https://localhost:9999")]
    [InlineData("https", "https://localhost:4200, https://evil.example")]
    public async Task InsecureOrCrossOriginRequest_IsRejectedBeforeConsumingChallenge(string scheme, string origin)
    {
        using var f = new WebAuthnAuthenticationCompletionTests.Fixture("https://localhost:4200");
        using var services = CreateServices();
        using var scope = services.CreateScope();
        var controller = CreateController(f, scope.ServiceProvider);
        controller.Request.Scheme = scheme;
        controller.Request.Headers.Origin = origin;
        var operation = f.Options.Generate();
        var request = new AuthenticationCompletionRequest { OperationId = operation.OperationId, Response = f.Response(operation.Options) };
        Assert.Equal(403, Assert.IsType<StatusCodeResult>(await controller.Complete(request, CancellationToken.None)).StatusCode);
        Assert.Equal(0, controller.Response.Headers.SetCookie.Count);
        controller.Request.Scheme = "https";
        controller.Request.Headers.Origin = "https://localhost:4200";
        Assert.IsType<OkObjectResult>(await controller.Complete(request, CancellationToken.None));
    }

    private static ServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(SafeNetCookieAuthentication.Configure);
        return services.BuildServiceProvider();
    }

    private static WebAuthnAuthenticationController CreateController(WebAuthnAuthenticationCompletionTests.Fixture fixture, IServiceProvider services)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Fido2:Origins:0"] = "https://localhost:4200"
        }).Build();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost", 4200);
        context.Request.Headers.Origin = "https://localhost:4200";
        return new WebAuthnAuthenticationController(new TestEnvironment(), fixture.Options, fixture.Completion, config)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Test";
        public string WebRootPath { get; set; } = "";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

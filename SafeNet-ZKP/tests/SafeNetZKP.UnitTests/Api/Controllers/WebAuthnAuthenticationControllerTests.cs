using Fido2NetLib;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public class WebAuthnAuthenticationControllerTests
{
    [Theory]
    [InlineData("Development", 200)]
    [InlineData("Production", 503)]
    public void GetOptions_RespectsEnvironmentAndDisablesCaching(string environment, int expectedStatus)
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnAuthenticationStore(cache);
        IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
        {
            RPID = "localhost", RPName = "SafeNet", ChallengeSize = 32,
            Origins = new HashSet<string> { "http://localhost:4200" }
        });
        var controller = new WebAuthnAuthenticationController(
            new TestEnvironment { EnvironmentName = environment },
            new WebAuthnAuthenticationOptionsService(fido, store), null!)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        var result = controller.GetOptions();
        Assert.Equal(expectedStatus, Assert.IsAssignableFrom<IStatusCodeActionResult>(result).StatusCode);
        Assert.Equal("no-store", controller.Response.Headers.CacheControl.ToString());
        if (expectedStatus == 200)
        {
            var body = Assert.IsType<AuthenticationOptionsResponse>(Assert.IsType<OkObjectResult>(result).Value);
            Assert.Equal("localhost", body.Options.GetProperty("rpId").GetString());
            Assert.NotNull(store.Take(body.OperationId));
        }
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

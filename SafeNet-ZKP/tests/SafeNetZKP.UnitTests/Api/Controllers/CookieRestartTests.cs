using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.IntegrationTests;
using SafeNetZKP.UnitTests.Api.Security;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed partial class CaptivePortalHttpTests
{
    [Fact]
    public Task WebAuthnCookieSurvivesRestartButNotEnvironmentChangeOrLogout() => VerifyCookieRestartAsync(null);

    [IsolatedPostgresFact]
    [Trait("Database", "PostgreSQL")]
    public Task PostgresWebAuthnCookieSurvivesRestartAndPreservesRevocation() =>
        VerifyCookieRestartAsync(TestDatabase.GetValidatedConnectionString());

    private static async Task VerifyCookieRestartAsync(string? connectionString)
    {
        var keys = Directory.CreateTempSubdirectory("safenet-test-keys-");
        var users = new InMemoryUserRepository();
        var sessions = new InMemorySessionRepository();
        var name = $"Cookie restart test {Guid.NewGuid():N}";
        using var rsa = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=SafeNet test ring", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        using var certificate = certificateRequest.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        void ShareTestRepositories(IWebHostBuilder builder)
        {
            builder.ConfigureServices(services =>
            {
                services.AddDataProtection().PersistKeysToFileSystem(keys)
                    .ProtectKeysWithCertificate(certificate).UnprotectKeysWithAnyCertificate(certificate);
                if (connectionString is not null)
                    return;
                services.RemoveAll<IUserRepository>();
                services.RemoveAll<IAuthenticatedSessionRepository>();
                services.AddSingleton<IUserRepository>(users);
                services.AddSingleton<IAuthenticatedSessionRepository>(sessions);
            });
        }

        Api Start(string environment = "Development") => new(environment, connectionString: connectionString,
            configure: ShareTestRepositories, usePersistentDataProtection: true);

        try
        {
            string cookie;
            SessionUserResponse expected;
            using (var first = Start())
            using (var client = first.Client())
            using (var key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var credentialId = RandomNumberGenerator.GetBytes(32);
                var user = await EnrollAsync(client, name, key, credentialId);
                (cookie, _) = await LoginAsync(first, client, user.UserId, key, credentialId, 1);
                expected = new SessionUserResponse(user.UserId, name);
            }

            var files = keys.GetFiles("key-*.xml");
            Assert.NotEmpty(files);
            Assert.All(files, file => Assert.Contains(XDocument.Load(file.FullName).Descendants(),
                element => element.Name.LocalName == "encryptedSecret"));

            using (var production = Start("Production"))
            using (var client = production.Client())
            {
                client.DefaultRequestHeaders.Add("Cookie", cookie);
                using var response = await client.GetAsync(Me);
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }

            using (var restarted = Start())
            using (var client = restarted.Client())
            {
                client.DefaultRequestHeaders.Add("Cookie", cookie);
                Assert.Equal(expected, await client.GetFromJsonAsync<SessionUserResponse>(Me));
                await restarted.AddCsrfAsync(client);
                using var logout = await client.PostAsync(Logout, null);
                Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
            }

            using var afterLogout = Start();
            using var replay = afterLogout.Client();
            replay.DefaultRequestHeaders.Add("Cookie", cookie);
            using var rejected = await replay.GetAsync(Me);
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }
        finally
        {
            keys.Delete(recursive: true);
            if (connectionString is not null)
                await DeletePostgresTestDataAsync(name);
        }
    }
}

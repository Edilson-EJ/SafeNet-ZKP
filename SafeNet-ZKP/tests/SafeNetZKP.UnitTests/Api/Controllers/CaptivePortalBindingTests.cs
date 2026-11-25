using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Infrastructure.CaptivePortal;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed partial class CaptivePortalHttpTests
{
    [Fact]
    public async Task LogoutDuringAssociationPreventsPublicationAndPersistence()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var reference = api.Stage(session);
        api.Transport.AfterAssociate = async () =>
        {
            using var logout = await session.Client.PostAsync(Logout, null);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        };

        using var response = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, api.Network.AssociationCount);
    }

    [Fact]
    public async Task FailedAssociationWriteDoesNotPublishBindingAndReferenceStaysConsumed()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var (connection, reference) = StageConnection(api, session);
        var request = new AssociateConnectionRequest(reference);
        api.Network.FailAssociations = true;
        using var failed = await session.Client.PostAsJsonAsync(Root + "/associations", request);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);

        api.Network.FailAssociations = false;
        using var retry = await session.Client.PostAsJsonAsync(Root + "/associations", request);
        Assert.Equal(HttpStatusCode.NotFound, retry.StatusCode);
        Assert.Equal(0, api.Network.AssociationCount);
        Assert.Null((await api.Transport.GetSessionAsync(connection, Ct)).Grant);
    }

    [Fact]
    public async Task RestartDoesNotRestoreUnconsumedIngressReferenceEvenWithValidSessionAndSurvivingGateway()
    {
        var protection = new EphemeralDataProtectionProvider();
        var sessions = new Security.InMemorySessionRepository();
        void ShareSessionInfrastructure(IWebHostBuilder builder) => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDataProtectionProvider>();
            services.AddSingleton<IDataProtectionProvider>(protection);
            services.RemoveAll<IAuthenticatedSessionRepository>();
            services.AddSingleton<IAuthenticatedSessionRepository>(sessions);
        });

        using var api = new Api(configure: ShareSessionInfrastructure);
        using var original = await api.SignInAsync();
        var reference = api.Stage(original);
        var cookie = Assert.Single(original.Client.DefaultRequestHeaders.GetValues("Cookie"));
        var gateway = api.Services.GetRequiredService<InMemoryCaptivePortalGateway>();
        api.Dispose();

        using var restarted = new Api(survivingGateway: gateway, configure: ShareSessionInfrastructure);
        using var client = restarted.Client();
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        await restarted.AddCsrfAsync(client);
        using var response = await client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, restarted.Network.AssociationCount);
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Api.Services;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.CaptivePortal;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.IntegrationTests;
using SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed partial class CaptivePortalHttpTests
{
    private const string Origin = "https://localhost";
    private const string Enrollment = "/api/webauthn/enrollment/";
    private const string Authentication = "/api/webauthn/authentication/";
    private const string Me = "/api/auth/me";
    private const string Logout = "/api/auth/logout";

    [Fact]
    public Task PasskeyToNetworkRevocationThroughHttp() => RunLifecycleAsync(null);

    [Theory]
    [InlineData("Development", true, true)]
    [InlineData("Development", false, false)]
    [InlineData("Production", true, false)]
    public void RevocationWorkerStartsOnlyWhenEnabledInDevelopment(string environment, bool enabled, bool expected)
    {
        using var api = new Api(environment, processRevocations: enabled);
        Assert.Equal(environment, api.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
        var worker = FindRevocationWorker(api);
        Assert.Equal(expected, worker is not null);
        if (worker is not null)
            Assert.NotNull(worker.ExecuteTask);
    }

    private static BackgroundService? FindRevocationWorker(Api api) =>
        api.Services.GetServices<IHostedService>().OfType<BackgroundService>()
            .SingleOrDefault(service => service.GetType().Name == "NetworkRevocationWorker");

    [IsolatedPostgresFact]
    [Trait("Database", "PostgreSQL")]
    public Task PostgresPasskeyToNetworkRevocationSurvivesHostRestart() =>
        RunLifecycleAsync(TestDatabase.GetValidatedConnectionString());

    private static async Task RunLifecycleAsync(string? connectionString)
    {
        using var api = new Api(connectionString: connectionString);
        using var client = api.Client();
        var name = $"Portal test {Guid.NewGuid():N}";
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var credentialId = RandomNumberGenerator.GetBytes(32);
            var registered = await EnrollAsync(client, name, key, credentialId);
            var (cookie, sessionId) = await LoginAsync(api, client, registered.UserId, key, credentialId, 1);
            using var owner = new Session(client, registered.UserId, sessionId);
            Assert.Equal(new SessionUserResponse(registered.UserId, name),
                await client.GetFromJsonAsync<SessionUserResponse>(Me));
            using var sessionIdOnly = api.Client();
            sessionIdOnly.DefaultRequestHeaders.Add("Cookie", $"__Host-SafeNetZKP={sessionId}");
            using var rejectedId = await sessionIdOnly.GetAsync(Me);
            Assert.Equal(HttpStatusCode.Unauthorized, rejectedId.StatusCode);

            using var secondClient = api.Client();
            var (_, secondId) = await LoginAsync(api, secondClient, registered.UserId, key, credentialId, 2);
            using var second = new Session(secondClient, registered.UserId, secondId);
            Assert.NotEqual(sessionId, secondId);

            var gateway = api.Services.GetRequiredService<InMemoryCaptivePortalGateway>();
            var (connection, reference) = StageConnection(api, owner);
            await api.AddCsrfAsync(owner.Client);
            await api.AddCsrfAsync(second.Client);
            using var stolen = await second.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
            Assert.Equal(HttpStatusCode.NotFound, stolen.StatusCode);
            var firstBinding = await AssociateAsync(owner, reference);
            var (secondConnection, secondReference) = StageConnection(api, second);
            var secondBinding = await AssociateAsync(second, secondReference);
            Assert.NotEqual(connection, secondConnection);

            var idempotencyKey = Guid.NewGuid();
            using var authorization = await AuthorizeAsync(owner, firstBinding, idempotencyKey);
            var operation = await ReadAsync(authorization, HttpStatusCode.OK, "authorized");
            using var repeated = await AuthorizeAsync(owner, firstBinding, idempotencyKey);
            Assert.Equal(operation, await ReadAsync(repeated, HttpStatusCode.OK, "authorized"));
            var location = Root + $"/operations/{operation.OperationId}";
            using var read = await client.GetAsync(location);
            Assert.Equal(operation, await ReadAsync(read, HttpStatusCode.OK, "authorized"));
            using var isolated = await second.Client.GetAsync(location);
            Assert.Equal(HttpStatusCode.NotFound, isolated.StatusCode);

            using var secondAuthorization = await AuthorizeAsync(second, secondBinding, Guid.NewGuid());
            var independent = await ReadAsync(secondAuthorization, HttpStatusCode.OK, "authorized");
            Assert.NotEqual(operation.OperationId, independent.OperationId);
            var observed = await gateway.GetOperationAsync(connection.GatewayId, operation.OperationId, Ct);
            Assert.Equal(NetworkAccessState.Authorized, observed.State);
            Assert.NotNull(observed.Grant);
            Assert.Equal(connection, observed.Grant.Connection);
            Assert.Equal(operation.ExpiresAt, observed.Grant.ExpiresAt);

            var csrf = Assert.Single(client.DefaultRequestHeaders.GetValues("X-CSRF-TOKEN"));
            client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
            using var rejectedLogout = await client.PostAsync(Logout, null);
            Assert.Equal(HttpStatusCode.BadRequest, rejectedLogout.StatusCode);
            Assert.NotNull(await client.GetFromJsonAsync<SessionUserResponse>(Me));

            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf);
            using var logout = await client.PostAsync(Logout, null);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
            Assert.Contains(logout.Headers.GetValues("Set-Cookie"), value =>
                value.StartsWith("__Host-SafeNetZKP=;", StringComparison.Ordinal));

            using var replay = api.Client();
            replay.DefaultRequestHeaders.Add("Cookie", cookie);
            using var rejectedReplay = await replay.GetAsync(Me);
            Assert.Equal(HttpStatusCode.Unauthorized, rejectedReplay.StatusCode);
            using var rejectedOperation = await replay.GetAsync(location);
            Assert.Equal(HttpStatusCode.Unauthorized, rejectedOperation.StatusCode);

            var pending = await ReadQueueAsync(api, operation.OperationId);
            Assert.NotNull(pending.RevocationId);
            Assert.Equal(NetworkAccessState.Pending, pending.RevocationState);
            Assert.Equal(NetworkAccessState.Authorized,
                (await gateway.GetOperationAsync(connection.GatewayId, operation.OperationId, Ct)).State);

            if (connectionString is null)
            {
                await using var scope = api.Services.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<NetworkRevocationProcessor>().ProcessPendingAsync(10, Ct);
            }
            else
            {
                api.Dispose();
                using var restarted = new Api(connectionString: connectionString, survivingGateway: gateway,
                    processRevocations: true);
                Assert.Same(gateway, restarted.Services.GetRequiredService<InMemoryCaptivePortalGateway>());
                await WaitForRevocationAsync(restarted, pending);
            }

            var revoked = await gateway.GetOperationAsync(connection.GatewayId, pending.RevocationId.Value, Ct);
            Assert.Equal(NetworkAccessState.Revoked, revoked.State);
            Assert.Equal(NetworkAccessState.Revoked, (await gateway.GetSessionAsync(connection, Ct)).Grant?.State);
            Assert.Equal(NetworkAccessState.Authorized,
                (await gateway.GetOperationAsync(secondConnection.GatewayId, independent.OperationId, Ct)).State);
        }
        finally
        {
            if (connectionString is not null)
                await DeletePostgresTestDataAsync(name);
        }
    }

    private static async Task WaitForRevocationAsync(Api api, NetworkAccessEntry pending)
    {
        var worker = FindRevocationWorker(api);
        var lastState = pending.RevocationState;
        string Describe() =>
            $"Last persisted revocation state: {lastState?.ToString() ?? "none"}. " +
            $"Worker registered: {worker is not null}. Worker started: {worker?.ExecuteTask is not null}. " +
            $"Worker task status: {worker?.ExecuteTask?.Status.ToString() ?? "none"}. " +
            $"Worker exception type: {worker?.ExecuteTask?.Exception?.GetBaseException().GetType().Name ?? "none"}.";

        Assert.True(worker?.ExecuteTask is not null, Describe());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            do
            {
                lastState = (await ReadQueueAsync(api, pending.Id, timeout.Token)).RevocationState;
                if (lastState == NetworkAccessState.Revoked)
                    return;

                Assert.False(worker.ExecuteTask.IsCompleted, Describe());
                await Task.Delay(TimeSpan.FromMilliseconds(100), timeout.Token);
            }
            while (true);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            Assert.Fail($"The restarted host did not persist a confirmed revocation within 15 seconds. {Describe()}");
        }
    }

    [Fact]
    public async Task ExpiredReferenceIsRejectedEvenWhenIngressStillHasObservation()
    {
        var clock = new PortalTestClock();
        using var api = new Api(clock: clock);
        using var session = await api.SignInAsync();
        var (_, reference) = StageConnection(api, session, TimeSpan.FromSeconds(10));
        clock.Now += TimeSpan.FromSeconds(11);
        using var response = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, api.Network.OperationCount);
    }

    [Fact]
    public async Task DatabaseFailureDuringReservationDoesNotCallGateway()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var (connection, reference) = StageConnection(api, session);
        var binding = await AssociateAsync(session, reference);
        api.Network.FailReservations = true;
        api.Transport.AfterAuthorize = () => throw new InvalidOperationException("Gateway called without persisting a reservation.");
        using var response = await AuthorizeAsync(session, binding, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, api.Network.OperationCount);
        Assert.Null((await api.Transport.GetSessionAsync(connection, Ct)).Grant);
    }

    private static (NetworkConnectionKey Connection, string Reference) StageConnection(Api api, Session session,
        TimeSpan? referenceLifetime = null, SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
    {
        var gateway = api.Services.GetRequiredService<InMemoryCaptivePortalGateway>();
        var observation = gateway.ObserveConnection(TimeSpan.FromMinutes(10), behavior);
        var reference = gateway.IssueAssociationReference(observation,
            AuthenticatedSessionService.GetAssociationReference(session.Id), referenceLifetime ?? TimeSpan.FromMinutes(1));
        api.Services.GetRequiredService<CaptivePortalIngress>()
            .StageObservation(session.Id, observation, reference,
                api.Services.GetRequiredService<TimeProvider>().GetUtcNow().AddMinutes(1));
        return (observation.Key, reference);
    }

    private static async Task<StartEnrollmentResult> EnrollAsync(HttpClient client, string name, ECDsa key, byte[] id)
    {
        using var start = await client.PostAsJsonAsync(Enrollment + "start", new StartEnrollmentRequest { Name = name });
        start.EnsureSuccessStatusCode();
        var user = (await start.Content.ReadFromJsonAsync<StartEnrollmentResult>())!;
        using var options = await client.PostAsJsonAsync(Enrollment + "options",
            new EnrollmentOptionsRequest { EnrollmentToken = user.EnrollmentToken });
        options.EnsureSuccessStatusCode();
        var challenge = (await options.Content.ReadFromJsonAsync<EnrollmentOptionsResponse>())!;
        using var completed = await client.PostAsJsonAsync(Enrollment + "complete", new CompleteRegistrationRequest
        {
            OperationId = challenge.OperationId,
            EnrollmentToken = user.EnrollmentToken,
            Response = WebAuthnRegistrationCompletionTests.MakeResponse(
                CredentialCreateOptions.FromJson(challenge.Options.GetRawText()), key, id, Origin)
        });
        Assert.True(completed.StatusCode == HttpStatusCode.NoContent,
            $"{completed.StatusCode}: {await completed.Content.ReadAsStringAsync()}");
        Assert.False(completed.Headers.Contains("Set-Cookie"));
        return user;
    }

    private static async Task<(string Cookie, string SessionId)> LoginAsync(Api api, HttpClient client,
        Guid userId, ECDsa key, byte[] id, uint counter)
    {
        using var start = await client.PostAsync(Authentication + "options", null);
        start.EnsureSuccessStatusCode();
        var challenge = (await start.Content.ReadFromJsonAsync<AuthenticationOptionsResponse>())!;
        using var request = new HttpRequestMessage(HttpMethod.Post, Authentication + "complete")
        {
            Content = JsonContent.Create(new AuthenticationCompletionRequest
            {
                OperationId = challenge.OperationId,
                Response = WebAuthnAuthenticationCompletionTests.Fixture.MakeResponse(
                    AssertionOptions.FromJson(challenge.Options.GetRawText()), key, id, userId, Origin, counter)
            })
        };
        request.Headers.Add("Origin", Origin);
        using var login = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(userId, (await login.Content.ReadFromJsonAsync<AuthenticationCompletionResponse>())?.UserId);
        var header = Assert.Single(login.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith("__Host-SafeNetZKP=", header);
        Assert.Contains("; secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; samesite=strict", header, StringComparison.OrdinalIgnoreCase);
        var cookie = header.Split(';')[0];
        var options = api.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        // Read the issued ticket only to supply the trusted in-process ingress context.
        var ticket = options.TicketDataFormat.Unprotect(cookie[(cookie.IndexOf('=') + 1)..]);
        Assert.NotNull(ticket);
        return (cookie, Assert.IsType<string>(SafeNetCookieAuthentication.GetSessionId(ticket.Properties)));
    }

    private static async Task<NetworkAccessEntry> ReadQueueAsync(Api api, Guid id, CancellationToken ct = default)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<INetworkAccessRepository>();
        if (repository is HttpNetworkRepository memory)
            return Assert.Single(await memory.ListPendingRevocationsAsync(10, ct), row => row.Id == id);
        var db = scope.ServiceProvider.GetRequiredService<SafeNetZKP.Infrastructure.Persistence.SafeNetZkpDbContext>();
        return await db.NetworkAccessOperations.AsNoTracking().SingleAsync(row => row.Id == id, ct);
    }

    private static async Task DeletePostgresTestDataAsync(string name)
    {
        await using var db = TestDatabase.CreateContext();
        var users = db.Users.Where(user => user.Name == name);
        var associations = db.NetworkAccessAssociations.Where(row => users.Any(user => user.Id == row.UserId));
        await db.NetworkAccessOperations.Where(row => associations.Any(association => association.Id == row.AssociationId))
            .ExecuteDeleteAsync();
        await associations.ExecuteDeleteAsync();
        await users.ExecuteDeleteAsync();
    }

    private static void RegisterInMemoryIdentity(IServiceCollection services)
    {
        services.RemoveAll<IUserRepository>();
        services.RemoveAll<IWebAuthnCredentialRepository>();
        services.RemoveAll<IWebAuthnCounterRepository>();
        services.AddSingleton<IUserRepository, InMemoryUserRepository>();
        services.AddSingleton<HttpCredentialRepository>();
        services.AddSingleton<IWebAuthnCredentialRepository>(provider => provider.GetRequiredService<HttpCredentialRepository>());
        services.AddSingleton<IWebAuthnCounterRepository>(provider => provider.GetRequiredService<HttpCredentialRepository>());
    }

    private sealed class HttpCredentialRepository : IWebAuthnCredentialRepository, IWebAuthnCounterRepository
    {
        private readonly List<WebAuthnCredential> _credentials = [];

        public Task AddAsync(WebAuthnCredential credential, CancellationToken ct = default)
        {
            _credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task<WebAuthnCredential?> GetByCredentialIdAsync(byte[] id, CancellationToken ct = default) =>
            Task.FromResult(_credentials.SingleOrDefault(item => item.CredentialId.AsSpan().SequenceEqual(id)));

        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(Guid id, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<WebAuthnCredential>>(_credentials.Where(item => item.UserId == id).ToArray());

        public Task<bool> TryUpdateCounterAsync(Guid id, uint expectedCounter, uint newCounter, CancellationToken ct = default)
        {
            var credential = _credentials.Single(item => item.Id == id);
            if (credential.SignatureCounter != expectedCounter)
                return Task.FromResult(false);
            typeof(WebAuthnCredential).GetProperty(nameof(WebAuthnCredential.SignatureCounter))!
                .SetValue(credential, newCounter);
            return Task.FromResult(true);
        }
    }

    private sealed class IsolatedPostgresFactAttribute : FactAttribute
    {
        public IsolatedPostgresFactAttribute()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SAFENET_TEST_CONNECTION_STRING")))
                Skip = "SAFENET_TEST_CONNECTION_STRING is not configured.";
        }
    }

    private sealed class PortalTestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}

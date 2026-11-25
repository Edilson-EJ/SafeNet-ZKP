using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Api.Services;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.CaptivePortal;
using SafeNetZKP.UnitTests.Api.Security;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed partial class CaptivePortalHttpTests
{
    private const string Root = "/api/captive-portal";
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task AnonymousCannotReadOrWrite()
    {
        using var api = new Api();
        using var client = api.Client();
        using var list = await client.GetAsync(Root + "/grants");
        using var write = await client.PostAsJsonAsync(Root + "/operations", new AuthorizeNetworkRequest(Guid.NewGuid(), Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, write.StatusCode);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("revoked")]
    public async Task InvalidSessionCannotReadGrants(string state)
    {
        using var api = new Api();
        using var session = await api.SignInAsync(expired: state == "expired");
        if (state == "revoked")
            await api.RevokeSessionAsync(session);

        using var response = await session.Client.GetAsync(Root + "/grants");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task PlainHttpIsRejectedAndSecureSessionCanReadEmptyList()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        using var plain = await session.Client.GetAsync("http://localhost" + Root + "/grants");
        Assert.Equal(HttpStatusCode.Forbidden, plain.StatusCode);
        Assert.Empty((await session.Client.GetFromJsonAsync<NetworkGrantResponse[]>(Root + "/grants"))!);
    }

    [Fact]
    public async Task MissingOrInvalidCsrfDoesNotConsumeAssociation()
    {
        using var api = new Api();
        using var session = await api.SignInAsync(withCsrf: false);
        var reference = api.Stage(session);
        using var missing = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        session.Client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", "invalid");
        using var invalid = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        session.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        await api.AddCsrfAsync(session.Client);
        await AssociateAsync(session, reference);
    }

    [Fact]
    public async Task AssociationRequiresTrustedIngressForExactSessionAndReferenceIsSingleUse()
    {
        using var api = new Api();
        using var owner = await api.SignInAsync();
        using var otherSession = await api.SignInAsync(owner.UserId);
        var reference = api.Stage(owner);
        using var stolen = await otherSession.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.NotFound, stolen.StatusCode);
        using var arbitrary = await owner.Client.PostAsJsonAsync(Root + "/associations",
            new AssociateConnectionRequest(new string('A', 64)));
        Assert.Equal(HttpStatusCode.NotFound, arbitrary.StatusCode);
        using var guessed = await owner.Client.PostAsJsonAsync(Root + "/operations",
            new AuthorizeNetworkRequest(Guid.NewGuid(), Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.NotFound, guessed.StatusCode);
        await AssociateAsync(owner, reference);
        using var replay = await owner.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);
    }

    [Theory]
    [InlineData(SimulatedAuthorizationBehavior.Confirm, HttpStatusCode.OK, "authorized")]
    [InlineData(SimulatedAuthorizationBehavior.Deny, HttpStatusCode.Forbidden, "denied")]
    [InlineData(SimulatedAuthorizationBehavior.TimeoutAfterApplying, HttpStatusCode.Accepted, "indeterminate")]
    public async Task AuthorizationMapsGatewayResultAndCanBeReconciled(SimulatedAuthorizationBehavior behavior,
        HttpStatusCode code, string state)
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var id = await AssociateAsync(session, api.Stage(session, behavior));
        using var response = await AuthorizeAsync(session, id, Guid.NewGuid());
        var result = await ReadAsync(response, code, state);
        if (behavior == SimulatedAuthorizationBehavior.TimeoutAfterApplying)
        {
            Assert.NotNull(response.Headers.Location);
            Assert.Null(result.ExpiresAt);
            using var reconciled = await session.Client.GetAsync(response.Headers.Location);
            await ReadAsync(reconciled, HttpStatusCode.OK, "authorized");
        }
    }

    [Fact]
    public async Task OwnershipIsEnforcedAndRevocationCanBeRepeated()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        using var other = await api.SignInAsync(session.UserId);
        using var stranger = await api.SignInAsync();
        var id = await AssociateAsync(session, api.Stage(session));
        using var authorization = await AuthorizeAsync(session, id, Guid.NewGuid());
        var operation = await ReadAsync(authorization, HttpStatusCode.OK, "authorized");
        var location = Root + $"/operations/{operation.OperationId}";
        using var otherRead = await other.Client.GetAsync(location);
        using var otherWrite = await stranger.Client.PostAsync(location + "/revocation", null);
        Assert.Equal(HttpStatusCode.NotFound, otherRead.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, otherWrite.StatusCode);
        Assert.Empty((await other.Client.GetFromJsonAsync<NetworkGrantResponse[]>(Root + "/grants"))!);
        var own = Assert.Single((await session.Client.GetFromJsonAsync<NetworkGrantResponse[]>(Root + "/grants"))!);
        Assert.Equal(operation.OperationId, own.OperationId);

        using var first = await session.Client.PostAsync(location + "/revocation", null);
        using var repeated = await session.Client.PostAsync(location + "/revocation", null);
        Assert.Equal(await ReadAsync(first, HttpStatusCode.Accepted, "pending"),
            await ReadAsync(repeated, HttpStatusCode.Accepted, "pending"));
        Assert.Equal(1, api.Network.RevocationCount);

        await using var scope = api.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<NetworkRevocationProcessor>().ProcessPendingAsync(10, Ct);
        using var terminal = await session.Client.GetAsync(location);
        await ReadAsync(terminal, HttpStatusCode.OK, "revoked");
    }

    [Fact]
    public async Task ConcurrentRequestsShareOneOperation()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var binding = await AssociateAsync(session, api.Stage(session));
        var key = Guid.NewGuid();
        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => AuthorizeAsync(session, binding, key)));
        var ids = new HashSet<Guid>();
        foreach (var response in responses)
        {
            using (response)
            {
                Assert.Contains(response.StatusCode, new[] { HttpStatusCode.OK, HttpStatusCode.Accepted });
                ids.Add((await response.Content.ReadFromJsonAsync<NetworkOperationResponse>())!.OperationId);
            }
        }
        Assert.Single(ids);
        Assert.Equal(1, api.Network.OperationCount);
    }

    [Fact]
    public async Task DatabaseFailureAfterAuthenticationReturns503WithoutState()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        api.Network.FailReads = true;
        using var response = await session.Client.GetAsync(Root + "/grants");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(problem.TryGetProperty("state", out _));
        Assert.False(problem.TryGetProperty("detail", out _));
    }

    [Fact]
    public async Task UnavailableGatewayNeverConfirmsAuthorization()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var binding = await AssociateAsync(session, api.Stage(session));
        api.Transport.Unavailable = true;
        var key = Guid.NewGuid();
        using var response = await AuthorizeAsync(session, binding, key);
        var result = await ReadAsync(response, HttpStatusCode.Accepted, "indeterminate");
        Assert.Null(result.ExpiresAt);
        api.Transport.Unavailable = false;
        using var recovered = await AuthorizeAsync(session, binding, key);
        Assert.Equal(result.OperationId, (await ReadAsync(recovered, HttpStatusCode.OK, "authorized")).OperationId);
        Assert.Equal(1, api.Network.OperationCount);
    }

    [Fact]
    public async Task LostGatewayStateMakesConfirmedAuthorizationIndeterminateAndPreventsResend()
    {
        var clock = new PortalTestClock();
        using var api = new Api(clock: clock);
        using var session = await api.SignInAsync();
        var binding = await AssociateAsync(session, api.Stage(session));
        var key = Guid.NewGuid();
        using var confirmed = await AuthorizeAsync(session, binding, key);
        var original = await ReadAsync(confirmed, HttpStatusCode.OK, "authorized");
        var location = Root + $"/operations/{original.OperationId}";

        api.Transport.Simulator = new InMemoryCaptivePortalGateway(clock);
        api.Transport.AfterAuthorize = () => throw new InvalidOperationException("Previously confirmed grant was resent.");
        using var reconciled = await session.Client.GetAsync(location);
        Assert.Null((await ReadAsync(reconciled, HttpStatusCode.OK, "indeterminate")).ExpiresAt);
        using var repeat = await AuthorizeAsync(session, binding, key);
        Assert.Equal(original.OperationId, (await ReadAsync(repeat, HttpStatusCode.Accepted, "indeterminate")).OperationId);
        Assert.Equal(1, api.Network.OperationCount);

        clock.Now = original.ExpiresAt!.Value;
        using var expired = await session.Client.GetAsync(location);
        await ReadAsync(expired, HttpStatusCode.OK, "expired");
    }

    [Fact]
    public async Task RevocationDuringGatewayCallSuppressesConfirmation()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        var (connection, reference) = StageConnection(api, session);
        var binding = await AssociateAsync(session, reference);
        api.Transport.AfterAuthorize = async () =>
        {
            using var logout = await session.Client.PostAsync(Logout, null);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        };
        using var response = await AuthorizeAsync(session, binding, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var pending = Assert.Single(await api.Network.ListPendingRevocationsAsync(10, Ct));
        Assert.Equal(NetworkAccessState.Pending, pending.RevocationState);
        Assert.Null(pending.ConfirmedUntil);
        var gateway = api.Services.GetRequiredService<InMemoryCaptivePortalGateway>();
        Assert.Equal(NetworkAccessState.Authorized, (await gateway.GetSessionAsync(connection, Ct)).Grant?.State);
        await using var scope = api.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<NetworkRevocationProcessor>().ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Revoked, (await gateway.GetSessionAsync(connection, Ct)).Grant?.State);
    }

    [Fact]
    public async Task RoutesAreNotRegisteredOutsideDevelopment()
    {
        using var api = new Api("Production");
        using var session = await api.SignInAsync();
        using var read = await session.Client.GetAsync(Root + "/grants");
        using var write = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(new string('A', 64)));
        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, write.StatusCode);
    }

    [Fact]
    public async Task WritesAreRateLimited()
    {
        using var api = new Api();
        using var session = await api.SignInAsync();
        for (var i = 0; i < 13; i++)
        {
            using var response = await session.Client.PostAsJsonAsync(Root + "/associations",
                new AssociateConnectionRequest(new string('A', 64)));
            Assert.Equal(i < 12 ? HttpStatusCode.NotFound : HttpStatusCode.TooManyRequests, response.StatusCode);
        }
    }

    private static async Task<Guid> AssociateAsync(Session session, string reference)
    {
        using var response = await session.Client.PostAsJsonAsync(Root + "/associations", new AssociateConnectionRequest(reference));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        return (await response.Content.ReadFromJsonAsync<NetworkAssociationResponse>())!.AssociationId;
    }

    private static Task<HttpResponseMessage> AuthorizeAsync(Session session, Guid binding, Guid key) =>
        session.Client.PostAsJsonAsync(Root + "/operations", new AuthorizeNetworkRequest(binding, key));

    private static async Task<NetworkOperationResponse> ReadAsync(HttpResponseMessage response, HttpStatusCode code, string state)
    {
        Assert.Equal(code, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<NetworkOperationResponse>();
        Assert.NotNull(payload);
        Assert.Equal(state, payload.State);
        return payload;
    }

    private sealed class Session(HttpClient client, Guid userId, string id) : IDisposable
    {
        public HttpClient Client { get; } = client;
        public Guid UserId { get; } = userId;
        public string Id { get; } = id;
        public void Dispose() => Client.Dispose();
    }

    private sealed class Api(string environment = "Development", string? connectionString = null,
        InMemoryCaptivePortalGateway? survivingGateway = null, bool processRevocations = false,
        TimeProvider? clock = null, Action<IWebHostBuilder>? configure = null,
        bool usePersistentDataProtection = false) : WebApplicationFactory<Program>
    {
        public HttpNetworkRepository Network { get; } = new();
        public TransportGateway Transport => Services.GetRequiredService<TransportGateway>();

        public HttpClient Client() => CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        public async Task<Session> SignInAsync(Guid? userId = null, bool expired = false, bool withCsrf = true)
        {
            var client = Client();
            var id = userId ?? Guid.NewGuid();
            await using var scope = Services.CreateAsyncScope();
            var properties = await InMemorySessionRepository.IssueAsync(scope.ServiceProvider, id);
            if (expired)
                properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
            const string scheme = CookieAuthenticationDefaults.AuthenticationScheme;
            var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
            var ticket = new AuthenticationTicket(SafeNetCookieAuthentication.CreatePrincipal(id), properties, scheme);
            client.DefaultRequestHeaders.Add("Cookie", $"{options.Cookie.Name}={options.TicketDataFormat.Protect(ticket)}");
            if (withCsrf && !expired)
                await AddCsrfAsync(client);
            return new Session(client, id, SafeNetCookieAuthentication.GetSessionId(properties)!);
        }

        public async Task AddCsrfAsync(HttpClient client)
        {
            var csrf = await client.GetFromJsonAsync<CsrfTokenResponse>("/api/auth/csrf");
            Assert.NotNull(csrf);
            client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf.Token);
        }

        public string Stage(Session session, SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm) =>
            StageConnection(this, session, behavior: behavior).Reference;

        public async Task RevokeSessionAsync(Session session)
        {
            await using var scope = Services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AuthenticatedSessionService>().RevokeAsync(session.Id, session.UserId, Ct);
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(config => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Fido2:RPID"] = "localhost",
                ["Fido2:RPName"] = "SafeNet Tests",
                ["Fido2:Origins:0"] = "https://localhost",
                // Program reads this while registering services, before web-host app configuration.
                ["CaptivePortal:ProcessRevocations"] = processRevocations.ToString()
            }));
            return base.CreateHost(builder);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = connectionString ?? ""
                }));
            builder.ConfigureLogging(logging =>
            {
                if (OperatingSystem.IsWindows())
                    logging.AddFilter<EventLogLoggerProvider>(null, LogLevel.None);
            });
            builder.ConfigureServices(services =>
            {
                if (!usePersistentDataProtection)
                    services.AddDataProtection().UseEphemeralDataProtectionProvider();
                if (clock is not null)
                {
                    services.RemoveAll<TimeProvider>();
                    services.AddSingleton(clock);
                }
                if (connectionString is null)
                {
                    services.RemoveAll<IAuthenticatedSessionRepository>();
                    services.AddSingleton<IAuthenticatedSessionRepository>(new InMemorySessionRepository
                    {
                        OnRevoked = Network.QueueSessionRevocations
                    });
                    services.RemoveAll<INetworkAccessRepository>();
                    services.AddSingleton<INetworkAccessRepository>(Network);
                    RegisterInMemoryIdentity(services);
                }
                if (survivingGateway is not null)
                {
                    services.RemoveAll<InMemoryCaptivePortalGateway>();
                    services.AddSingleton(survivingGateway);
                }
                services.RemoveAll<ICaptivePortalGateway>();
                services.RemoveAll<ICaptivePortalAssociationGateway>();
                services.AddSingleton<TransportGateway>();
                services.AddSingleton<ICaptivePortalGateway>(provider => provider.GetRequiredService<TransportGateway>());
                services.AddSingleton<ICaptivePortalAssociationGateway>(provider => provider.GetRequiredService<TransportGateway>());
            });
            configure?.Invoke(builder);
        }
    }

    private sealed class TransportGateway(InMemoryCaptivePortalGateway inner)
        : ICaptivePortalGateway, ICaptivePortalAssociationGateway
    {
        public InMemoryCaptivePortalGateway Simulator { get; set; } = inner;
        public bool Unavailable { get; set; }
        public Func<Task>? AfterAuthorize { get; set; }
        public Func<Task>? AfterAssociate { get; set; }

        public async Task<NetworkAssociation?> AssociateAsync(ObservedNetworkConnection observation,
            NetworkAssociationRequest request, CancellationToken ct)
        {
            var result = await Simulator.AssociateAsync(observation, request, ct);
            if (AfterAssociate is { } after)
                await after();
            return result;
        }

        public async Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request, CancellationToken ct)
        {
            if (Unavailable)
                throw new GatewayCommunicationException();
            var result = await Simulator.AuthorizeAsync(request, ct);
            if (AfterAuthorize is { } after)
                await after();
            return result;
        }

        public Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection, CancellationToken ct) =>
            Simulator.GetSessionAsync(connection, ct);
        public Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId, CancellationToken ct) =>
            Unavailable ? throw new GatewayCommunicationException() : Simulator.GetOperationAsync(gatewayId, operationId, ct);
        public Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request, CancellationToken ct) =>
            Simulator.RevokeAsync(request, ct);
    }

    private sealed class HttpNetworkRepository : INetworkAccessRepository
    {
        private readonly object _lock = new();
        private readonly Dictionary<Guid, NetworkAccessAssociation> _associations = new();
        private readonly Dictionary<Guid, Row> _rows = new();

        public bool FailReads { get; set; }
        public bool FailReservations { get; set; }
        public bool FailAssociations { get; set; }
        public int AssociationCount => _associations.Count;
        public int OperationCount => _rows.Count;
        public int RevocationCount => _rows.Values.Count(row => row.RevocationId is not null);

        public Task<bool> AddAssociationAsync(NetworkAccessAssociation association, CancellationToken ct)
        {
            if (FailAssociations)
                throw new UnavailableDatabaseException();
            lock (_lock)
                return Task.FromResult(_associations.TryAdd(association.Id, association));
        }

        public Task<(NetworkAccessEntry? Entry, bool Created)> ReserveAsync(Guid associationId, Guid userId,
            byte[] sessionHash, Guid idempotencyKey, DateTimeOffset now, DateTimeOffset validUntil,
            DateTimeOffset accessUntil, CancellationToken ct)
        {
            if (FailReservations)
                throw new UnavailableDatabaseException();
            lock (_lock)
            {
                if (!_associations.TryGetValue(associationId, out var association) || !Owns(association, userId, sessionHash))
                    return Task.FromResult<(NetworkAccessEntry?, bool)>((null, false));
                var existing = _rows.Values.SingleOrDefault(row =>
                    row.Entry.AssociationId == associationId && row.Entry.IdempotencyKey == idempotencyKey);
                if (existing is not null)
                    return Task.FromResult<(NetworkAccessEntry?, bool)>((existing.Snapshot(), false));
                var entry = new NetworkAccessEntry
                {
                    Id = Guid.NewGuid(), AssociationId = associationId, Association = association,
                    IdempotencyKey = idempotencyKey, GrantId = Guid.NewGuid(), Revision = 1,
                    ValidUntil = validUntil, AccessUntil = accessUntil, CreatedAt = now
                };
                _rows.Add(entry.Id, new Row(entry));
                return Task.FromResult<(NetworkAccessEntry?, bool)>((entry, true));
            }
        }

        public Task<NetworkAccessEntry?> FindOwnedAsync(Guid operationId, Guid userId, byte[] sessionHash, CancellationToken ct)
        {
            lock (_lock)
                return Task.FromResult(_rows.TryGetValue(operationId, out var row) &&
                    Owns(row.Entry.Association, userId, sessionHash) ? row.Snapshot() : null);
        }

        public Task<IReadOnlyList<NetworkAccessEntry>> ListOwnedAsync(Guid userId, byte[] sessionHash, int limit, CancellationToken ct)
        {
            if (FailReads)
                throw new UnavailableDatabaseException();
            lock (_lock)
                return Task.FromResult<IReadOnlyList<NetworkAccessEntry>>(_rows.Values
                    .Where(row => Owns(row.Entry.Association, userId, sessionHash)).Take(limit)
                    .Select(row => row.Snapshot()).ToArray());
        }

        public Task RecordAuthorizationAsync(Guid id, NetworkAccessState state, DateTimeOffset? confirmedUntil,
            DateTimeOffset now, CancellationToken ct)
        {
            lock (_lock)
            {
                var row = _rows[id];
                if (row.RevocationId is null)
                {
                    row.State = state == NetworkAccessState.Denied && row.GrantState == NetworkAccessState.Authorized
                        ? NetworkAccessState.Indeterminate : state;
                    if (state == NetworkAccessState.Authorized)
                    {
                        row.GrantState = state;
                        row.ConfirmedUntil = confirmedUntil;
                    }
                }
                return Task.CompletedTask;
            }
        }

        public Task<bool> QueueRevocationAsync(Guid id, Guid userId, byte[] sessionHash, DateTimeOffset now, CancellationToken ct)
        {
            lock (_lock)
            {
                if (!_rows.TryGetValue(id, out var row) || !Owns(row.Entry.Association, userId, sessionHash))
                    return Task.FromResult(false);
                row.RevocationId ??= Guid.NewGuid();
                row.RevocationState ??= NetworkAccessState.Pending;
                return Task.FromResult(true);
            }
        }

        public void QueueSessionRevocations(Guid userId, byte[] sessionHash)
        {
            lock (_lock)
            {
                foreach (var row in _rows.Values.Where(row => Owns(row.Entry.Association, userId, sessionHash)))
                {
                    row.RevocationId ??= Guid.NewGuid();
                    row.RevocationState ??= NetworkAccessState.Pending;
                }
            }
        }

        public Task<IReadOnlyList<NetworkAccessEntry>> ListPendingRevocationsAsync(int limit, CancellationToken ct)
        {
            lock (_lock)
                return Task.FromResult<IReadOnlyList<NetworkAccessEntry>>(_rows.Values
                    .Where(row => row.RevocationState is NetworkAccessState.Pending or NetworkAccessState.Indeterminate)
                    .Take(limit).Select(row => row.Snapshot()).ToArray());
        }

        public Task RecordRevocationAsync(Guid id, Guid revocationId, NetworkAccessState state, DateTimeOffset now,
            CancellationToken ct)
        {
            lock (_lock)
            {
                if (_rows[id].RevocationId == revocationId)
                    _rows[id].RevocationState = state;
                return Task.CompletedTask;
            }
        }

        private static bool Owns(NetworkAccessAssociation association, Guid user, byte[] hash) =>
            association.UserId == user && association.SessionHash.AsSpan().SequenceEqual(hash);

        private sealed class Row(NetworkAccessEntry entry)
        {
            public NetworkAccessEntry Entry { get; } = entry;
            public NetworkAccessState State { get; set; }
            public NetworkAccessState? GrantState { get; set; }
            public DateTimeOffset? ConfirmedUntil { get; set; }
            public Guid? RevocationId { get; set; }
            public NetworkAccessState? RevocationState { get; set; }

            public NetworkAccessEntry Snapshot() => new()
            {
                Id = Entry.Id, AssociationId = Entry.AssociationId, Association = Entry.Association,
                IdempotencyKey = Entry.IdempotencyKey, GrantId = Entry.GrantId, Revision = Entry.Revision,
                ValidUntil = Entry.ValidUntil, AccessUntil = Entry.AccessUntil, CreatedAt = Entry.CreatedAt,
                ConfirmedUntil = ConfirmedUntil, State = State, GrantState = GrantState,
                RevocationId = RevocationId, RevocationState = RevocationState
            };
        }

        private sealed class UnavailableDatabaseException : DbException;
    }
}

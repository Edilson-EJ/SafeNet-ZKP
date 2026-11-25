using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.CaptivePortal;
using SafeNetZKP.UnitTests.Api.Security;

namespace SafeNetZKP.UnitTests.UseCases.CaptivePortal;

public sealed class NetworkAccessServiceTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task ActiveSessionAndTrustedObservationAuthorizeAccessOnce()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var (observation, reference) = lab.Connect(caller);
        var binding = await lab.AssociateAsync(caller, observation, reference);
        Assert.Null(await lab.Service.AssociateAsync(caller.Context, observation, reference, Ct));

        var operation = lab.Prepare(binding);
        var result = await lab.Service.AuthorizeAsync(caller.Context, operation, Ct);
        Assert.Equal(NetworkAccessState.Authorized, result.State);
        Assert.Equal(operation.Id, result.OperationId);
        Assert.Equal(observation.Key, result.Grant?.Connection);
        Assert.Equal(result, await lab.Service.GetOperationAsync(caller.Context, operation, Ct));
    }

    [Theory]
    [InlineData("anonymous")]
    [InlineData("missing")]
    [InlineData("malformed")]
    [InlineData("unknown")]
    [InlineData("wrong-user")]
    [InlineData("expired")]
    [InlineData("revoked")]
    public async Task InvalidSessionCannotConsumeAssociationReference(string state)
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var (observation, reference) = lab.Connect(caller);
        if (state == "expired")
            lab.Clock.Advance(AuthenticatedSessionService.Lifetime);
        if (state == "revoked")
            await lab.Sessions.RevokeAsync(caller.Identifier, caller.UserId, Ct);
        var context = state switch
        {
            "anonymous" => new NetworkAccessCaller(new UserContext(null), caller.Identifier),
            "missing" => new NetworkAccessCaller(new UserContext(caller.UserId), null),
            "malformed" => new NetworkAccessCaller(new UserContext(caller.UserId), Guid.NewGuid().ToString()),
            "unknown" => new NetworkAccessCaller(new UserContext(caller.UserId), new string('A', 64)),
            "wrong-user" => new NetworkAccessCaller(new UserContext(Guid.NewGuid()), caller.Identifier),
            _ => caller.Context
        };

        Assert.Null(await lab.Service.AssociateAsync(context, observation, reference, Ct));
        var replacement = await lab.SignInAsync(caller.UserId);
        Assert.Null(await lab.Service.AssociateAsync(replacement.Context, observation, reference, Ct));
        if (state is not ("expired" or "revoked"))
            await lab.AssociateAsync(caller, observation, reference);
    }

    [Fact]
    public async Task ArbitraryOrExpiredReferencesAndCopiedObservationsAreRejected()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var (observation, reference) = lab.Connect(caller);
        var (_, unrelatedReference) = lab.Connect(caller);
        Assert.Null(await lab.Service.AssociateAsync(caller.Context, observation, unrelatedReference, Ct));
        Assert.Null(await lab.Service.AssociateAsync(caller.Context, observation with { }, reference, Ct));
        lab.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Null(await lab.Service.AssociateAsync(caller.Context, observation, reference, Ct));
        await lab.AssociateAsync(caller, observation,
            lab.Gateway.IssueAssociationReference(observation,
                AuthenticatedSessionService.GetAssociationReference(caller.Identifier), TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public async Task ConcurrentUsersCannotBothBindSameConnection()
    {
        var lab = new Lab();
        var first = await lab.SignInAsync();
        var second = await lab.SignInAsync();
        var (observation, reference) = lab.Connect(first);
        var results = await Task.WhenAll(
            Task.Run(() => lab.Service.AssociateAsync(first.Context, observation, reference, Ct)),
            Task.Run(() => lab.Service.AssociateAsync(second.Context, observation, reference, Ct)));
        Assert.NotNull(results[0]);
        Assert.Null(results[1]);
    }

    [Fact]
    public async Task DevicesAreIndependentAndOtherSessionsCannotUseBinding()
    {
        var lab = new Lab();
        var first = await lab.SignInAsync();
        var otherSession = await lab.SignInAsync(first.UserId);
        var second = await lab.SignInAsync();
        var operationA = await lab.ConnectAndPrepareAsync(first);
        var operationB = await lab.ConnectAndPrepareAsync(second);

        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.AuthorizeAsync(otherSession.Context, operationA, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Service.AuthorizeAsync(first.Context, operationA, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Service.AuthorizeAsync(second.Context, operationB, Ct)).State);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.GetOperationAsync(second.Context, operationA, Ct)).State);
        var revoke = lab.PrepareRevocation(operationA);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.RevokeAsync(otherSession.Context, revoke, Ct)).State);
        Assert.Equal(NetworkAccessState.Revoked, (await lab.Service.RevokeAsync(first.Context, revoke, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Service.GetOperationAsync(second.Context, operationB, Ct)).State);
    }

    [Fact]
    public async Task GatewayDenialDoesNotReturnGrant()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller, SimulatedAuthorizationBehavior.Deny);
        var result = await lab.Service.AuthorizeAsync(caller.Context, operation, Ct);
        Assert.Equal(NetworkAccessState.Denied, result.State);
        Assert.Null(result.Grant);
        Assert.Equal(result, await lab.Service.GetOperationAsync(caller.Context, operation, Ct));
    }

    [Fact]
    public async Task TimeoutAfterApplyingNeedsReconciliation()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller, SimulatedAuthorizationBehavior.TimeoutAfterApplying);
        var result = await lab.Service.AuthorizeAsync(caller.Context, operation, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, result.State);
        Assert.Null(result.Grant);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Service.GetOperationAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task TransportFailureRemainsIndeterminateAndOriginalOperationCanBeRetried()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        lab.Transport.Fail = true;
        Assert.Equal(NetworkAccessState.Indeterminate,
            (await lab.Service.AuthorizeAsync(caller.Context, operation, Ct)).State);
        Assert.Equal(NetworkAccessState.Indeterminate,
            (await lab.Service.GetOperationAsync(caller.Context, operation, Ct)).State);
        lab.Transport.Fail = false;
        Assert.Equal(NetworkAccessState.Indeterminate,
            (await lab.Service.GetOperationAsync(caller.Context, operation, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Service.AuthorizeAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task ConcurrentDuplicatesUseOneGrantAndRepeatedRevocationIsSafe()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            Task.Run(() => lab.Service.AuthorizeAsync(caller.Context, operation, Ct))));
        var grant = Assert.IsType<NetworkAccessGrant>(results[0].Grant);
        Assert.All(results, result => Assert.Equal(grant, result.Grant));

        var revocation = lab.PrepareRevocation(operation);
        var revoked = await lab.Service.RevokeAsync(caller.Context, revocation, Ct);
        Assert.Equal(NetworkAccessState.Revoked, revoked.State);
        Assert.Equal(revoked, await lab.Service.RevokeAsync(caller.Context, revocation, Ct));
        Assert.Equal(revoked, await lab.Service.GetOperationAsync(caller.Context, revocation, Ct));
        Assert.Equal(NetworkAccessState.Revoked,
            (await lab.Service.AuthorizeAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task RevocationBeforeAuthorizationBlocksDelayedCommand()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        Assert.Equal(NetworkAccessState.Revoked,
            (await lab.Service.RevokeAsync(caller.Context, lab.PrepareRevocation(operation), Ct)).State);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.AuthorizeAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task UnsentCommandPastDeadlineIsOnlyQueried()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        lab.Clock.Advance(TimeSpan.FromMinutes(1));
        lab.Transport.AfterAuthorize = () => throw new InvalidOperationException("Expired command was dispatched.");
        Assert.Equal(NetworkAccessState.Indeterminate,
            (await lab.Service.AuthorizeAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task ExpiredGrantCannotBeReactivatedAndAccessIsCappedByStoredSessionExpiry()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var (observation, reference) = lab.Connect(caller);
        var binding = await lab.AssociateAsync(caller, observation, reference);
        var shortAccess = lab.Prepare(binding);
        await lab.Service.AuthorizeAsync(caller.Context, shortAccess, Ct);
        lab.Clock.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(NetworkAccessState.Expired,
            (await lab.Service.AuthorizeAsync(caller.Context, shortAccess, Ct)).State);

        var next = lab.Service.PrepareAuthorization(binding, 2, TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
        var result = await lab.Service.AuthorizeAsync(caller.Context, next, Ct);
        Assert.Equal(caller.ExpiresAt, result.Grant?.ExpiresAt);
        lab.Clock.Advance(TimeSpan.FromMinutes(15));
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.GetOperationAsync(caller.Context, next, Ct)).State);
        Assert.Equal(NetworkAccessState.Expired,
            (await lab.Gateway.GetSessionAsync(observation.Key, Ct)).Grant?.State);
    }

    [Fact]
    public async Task RevocationOfAuthenticatedSessionDuringGatewayCallSuppressesConfirmation()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        lab.Transport.AfterAuthorize = () => lab.Sessions.RevokeAsync(caller.Identifier, caller.UserId, Ct);
        var result = await lab.Service.AuthorizeAsync(caller.Context, operation, Ct);
        Assert.Equal(NetworkAccessState.Denied, result.State);
        Assert.Null(result.Grant);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Service.GetOperationAsync(caller.Context, operation, Ct)).State);
    }

    [Fact]
    public async Task WrongGrantInGatewayResponseIsNotConfirmed()
    {
        var lab = new Lab();
        var caller = await lab.SignInAsync();
        var operation = await lab.ConnectAndPrepareAsync(caller);
        lab.Transport.ChangeGrantId = true;
        var result = await lab.Service.AuthorizeAsync(caller.Context, operation, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, result.State);
        Assert.Null(result.Grant);
    }

    private sealed class Lab
    {
        public ManualClock Clock { get; } = new();
        public InMemoryCaptivePortalGateway Gateway { get; }
        public TransportGateway Transport { get; }
        public AuthenticatedSessionService Sessions { get; }
        public NetworkAccessService Service { get; }

        public Lab()
        {
            Gateway = new InMemoryCaptivePortalGateway(Clock);
            Transport = new TransportGateway(Gateway);
            Sessions = new AuthenticatedSessionService(new InMemorySessionRepository(), Clock);
            Service = new NetworkAccessService(Sessions, Gateway, Transport, Clock);
        }

        public async Task<Caller> SignInAsync(Guid? userId = null)
        {
            var id = userId ?? Guid.NewGuid();
            var session = await Sessions.CreateAsync(id, Ct);
            return new Caller(id, session.Id, session.ExpiresAt);
        }

        public (ObservedNetworkConnection Observation, string Reference) Connect(Caller caller,
            SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
        {
            var observation = Gateway.ObserveConnection(TimeSpan.FromHours(1), behavior);
            return (observation, Gateway.IssueAssociationReference(observation,
                AuthenticatedSessionService.GetAssociationReference(caller.Identifier), TimeSpan.FromMinutes(1)));
        }

        public async Task<NetworkAccessBinding> AssociateAsync(Caller caller,
            ObservedNetworkConnection observation, string reference) =>
            Assert.IsType<NetworkAccessBinding>(await Service.AssociateAsync(caller.Context, observation, reference, Ct));

        public async Task<NetworkAccessAuthorization> ConnectAndPrepareAsync(Caller caller,
            SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
        {
            var (observation, reference) = Connect(caller, behavior);
            return Prepare(await AssociateAsync(caller, observation, reference));
        }

        public NetworkAccessAuthorization Prepare(NetworkAccessBinding binding) =>
            Service.PrepareAuthorization(binding, 1, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));

        public NetworkAccessRevocation PrepareRevocation(NetworkAccessAuthorization operation) =>
            Service.PrepareRevocation(operation, 2, TimeSpan.FromMinutes(1));
    }

    private sealed class TransportGateway(ICaptivePortalGateway inner) : ICaptivePortalGateway
    {
        public bool Fail { get; set; }
        public bool ChangeGrantId { get; set; }
        public Func<Task>? AfterAuthorize { get; set; }

        public async Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request, CancellationToken ct)
        {
            if (Fail)
                throw new TimeoutException();

            var result = await inner.AuthorizeAsync(request, ct);
            if (AfterAuthorize is { } after)
                await after();
            return ChangeGrantId && result.Grant is { } grant
                ? result with { Grant = grant with { Id = Guid.NewGuid() } } : result;
        }

        public Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId, CancellationToken ct) =>
            Fail ? throw new GatewayCommunicationException() : inner.GetOperationAsync(gatewayId, operationId, ct);

        public Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request, CancellationToken ct) =>
            inner.RevokeAsync(request, ct);

        public Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection, CancellationToken ct) =>
            inner.GetSessionAsync(connection, ct);
    }

    private sealed class Caller(Guid userId, string identifier, DateTimeOffset expiresAt)
    {
        public Guid UserId { get; } = userId;
        public string Identifier { get; } = identifier;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public NetworkAccessCaller Context { get; } = new(new UserContext(userId), identifier);
    }

    private sealed class UserContext(Guid? userId) : ICurrentUserContext
    {
        public Guid? UserId { get; } = userId;
    }

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delay) => _now = _now.Add(delay);
    }
}

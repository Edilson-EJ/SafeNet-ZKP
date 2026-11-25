using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.CaptivePortal;

namespace SafeNetZKP.UnitTests.Infrastructure.CaptivePortal;

public sealed class InMemoryCaptivePortalGatewayTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task ConnectionsAndGrantsAreIndependent()
    {
        var lab = new Lab();
        var first = lab.Associate();
        var second = lab.Associate();
        Assert.NotEqual(first.Connection, second.Connection);
        var a = lab.Request(first);
        var b = lab.Request(second);
        Assert.Equal(NetworkAccessState.Authorized, (await lab.Gateway.AuthorizeAsync(a, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized, (await lab.Gateway.AuthorizeAsync(b, Ct)).State);

        var wrongTarget = lab.Revocation(b) with { GrantId = a.GrantId };
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.RevokeAsync(wrongTarget, Ct)).State);
        Assert.Equal(NetworkAccessState.Revoked, (await lab.Gateway.RevokeAsync(lab.Revocation(a), Ct)).State);
        Assert.Equal(NetworkAccessState.Revoked,
            (await lab.Gateway.GetSessionAsync(first.Connection, Ct)).Grant?.State);
        Assert.Equal(b.GrantId, (await lab.Gateway.GetSessionAsync(second.Connection, Ct)).Grant?.Id);
        Assert.Equal(NetworkAccessState.Authorized,
            (await lab.Gateway.GetOperationAsync(second.Connection.GatewayId, b.OperationId, Ct)).State);
    }

    [Fact]
    public async Task AssociationRequiresTrustedObservationAndConsumesReferenceOnce()
    {
        var lab = new Lab();
        var observation = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var other = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var request = lab.AssociationRequest(observation);
        var query = await lab.Gateway.GetSessionAsync(observation.Key, Ct);
        Assert.NotNull(query.Connection);
        Assert.Throws<InvalidOperationException>(() =>
            lab.Gateway.IssueAssociationReference(query.Connection, request.AuthenticatedSessionReference, TimeSpan.FromMinutes(1)));
        Assert.Null(lab.Gateway.Associate(query.Connection, request));
        Assert.Null(new InMemoryCaptivePortalGateway(lab.Clock).Associate(observation, request));
        Assert.Null(lab.Gateway.Associate(other, request));
        Assert.Null(lab.Gateway.Associate(observation, request with { Reference = "untrusted" }));

        var association = lab.Gateway.Associate(observation, request);
        Assert.NotNull(association);
        Assert.Equal(request.UserId, association.UserId);
        Assert.Equal(request.AuthenticatedSessionReference, association.AuthenticatedSessionReference);
        Assert.Null(lab.Gateway.Associate(observation, request));
        Assert.Null(lab.Gateway.Associate(observation, request with { UserId = Guid.NewGuid() }));
        Assert.Throws<InvalidOperationException>(() =>
            lab.Gateway.IssueAssociationReference(observation, request.AuthenticatedSessionReference, TimeSpan.FromMinutes(1)));

        var authorize = lab.Request(association);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Gateway.AuthorizeAsync(authorize with { Association = association with { } }, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized, (await lab.Gateway.AuthorizeAsync(authorize, Ct)).State);
    }

    [Fact]
    public void ExpiredAssociationReferenceCannotBeConsumed()
    {
        var lab = new Lab();
        var observation = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var expiring = lab.AssociationRequest(observation);
        lab.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Null(lab.Gateway.Associate(observation, expiring));
        Assert.NotNull(lab.Gateway.Associate(observation, lab.AssociationRequest(observation)));
    }

    [Fact]
    public async Task ConcurrentAssociationAttemptsCanOnlyBindOneUser()
    {
        var lab = new Lab();
        var observation = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var first = lab.AssociationRequest(observation);
        var second = first with { UserId = Guid.NewGuid(), AuthenticatedSessionReference = Guid.NewGuid() };
        Assert.Throws<InvalidOperationException>(() => lab.Gateway.IssueAssociationReference(observation,
            second.AuthenticatedSessionReference, TimeSpan.FromMinutes(1)));
        var results = await Task.WhenAll(Task.Run(() => lab.Gateway.Associate(observation, first)),
            Task.Run(() => lab.Gateway.Associate(observation, second)));
        Assert.NotNull(results[0]);
        Assert.Null(results[1]);
    }

    [Fact]
    public async Task ConcurrentDuplicatesCreateOneGrantAndChangedPayloadIsDenied()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate());
        var results = await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() => lab.Gateway.AuthorizeAsync(request, Ct))));
        var grant = Assert.IsType<NetworkAccessGrant>(results[0].Grant);
        Assert.All(results, result =>
        {
            Assert.Equal(NetworkAccessState.Authorized, result.State);
            Assert.Equal(grant, result.Grant);
        });
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.AuthorizeAsync(
            request with { AccessUntil = request.AccessUntil.AddMinutes(1) }, Ct)).State);
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.AuthorizeAsync(
            request with { OperationId = Guid.NewGuid(), GrantId = Guid.NewGuid(), Revision = 2 }, Ct)).State);
        Assert.Equal(grant, (await lab.Gateway.GetSessionAsync(request.Association.Connection, Ct)).Grant);
    }

    [Fact]
    public async Task PolicyDenialIsConfirmedAndDoesNotCreateGrant()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate(SimulatedAuthorizationBehavior.Deny));
        var denied = await lab.Gateway.AuthorizeAsync(request, Ct);
        Assert.Equal(NetworkAccessState.Denied, denied.State);
        Assert.Null(denied.Grant);
        Assert.Equal(denied, await lab.Gateway.GetOperationAsync(request.Association.Connection.GatewayId, request.OperationId, Ct));
        Assert.Null((await lab.Gateway.GetSessionAsync(request.Association.Connection, Ct)).Grant);
    }

    [Fact]
    public async Task TimeoutDoesNotConfirmAccessButStateCanBeReconciled()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate(SimulatedAuthorizationBehavior.TimeoutAfterApplying));
        var unknown = await lab.Gateway.AuthorizeAsync(request, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, unknown.State);
        Assert.Null(unknown.Grant);

        var gatewayId = request.Association.Connection.GatewayId;
        var confirmed = await lab.Gateway.GetOperationAsync(gatewayId, unknown.OperationId, Ct);
        Assert.Equal(NetworkAccessState.Authorized, confirmed.State);
        Assert.Equal(request.GrantId, confirmed.Grant?.Id);
        Assert.Equal(confirmed, await lab.Gateway.AuthorizeAsync(request, Ct));
        Assert.Equal(NetworkAccessState.Indeterminate,
            (await lab.Gateway.GetOperationAsync(gatewayId, Guid.NewGuid(), Ct)).State);
    }

    [Fact]
    public async Task ExpiryIsTerminalAndDuplicateCannotExtendGrant()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate());
        var authorized = await lab.Gateway.AuthorizeAsync(request, Ct);
        Assert.Equal(request.AccessUntil, authorized.Grant?.ExpiresAt);
        lab.Clock.Advance(TimeSpan.FromMinutes(5));
        var expired = await lab.Gateway.AuthorizeAsync(request, Ct);
        Assert.Equal(NetworkAccessState.Expired, expired.State);
        Assert.Equal(authorized.Grant?.ExpiresAt, expired.Grant?.ExpiresAt);

        var next = lab.Request(request.Association, revision: 2);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Gateway.AuthorizeAsync(next with { GrantId = request.GrantId }, Ct)).State);
        Assert.Equal(NetworkAccessState.Authorized, (await lab.Gateway.AuthorizeAsync(next, Ct)).State);
    }

    [Fact]
    public async Task AccessIsCappedByAuthenticatedSessionDeadline()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate()) with { AccessUntil = lab.Clock.GetUtcNow().AddHours(1) };
        var grant = (await lab.Gateway.AuthorizeAsync(request, Ct)).Grant;
        Assert.NotNull(grant);
        Assert.Equal(request.Association.ExpiresAt, grant.ExpiresAt);
        lab.Clock.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal(NetworkAccessState.Expired,
            (await lab.Gateway.GetSessionAsync(request.Association.Connection, Ct)).Grant?.State);
        Assert.Equal(NetworkAccessState.Denied,
            (await lab.Gateway.AuthorizeAsync(lab.Request(request.Association, revision: 2), Ct)).State);
    }

    [Fact]
    public async Task RevocationIsIdempotentAndCannotReopenAnOldGrant()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate());
        await lab.Gateway.AuthorizeAsync(request, Ct);
        var revoke = lab.Revocation(request);
        var revoked = await lab.Gateway.RevokeAsync(revoke, Ct);
        Assert.Equal(NetworkAccessState.Revoked, revoked.State);
        Assert.Equal(revoked, await lab.Gateway.RevokeAsync(revoke, Ct));
        Assert.Equal(NetworkAccessState.Revoked, (await lab.Gateway.RevokeAsync(
            revoke with { Revision = 3, OperationId = Guid.NewGuid() }, Ct)).State);
        Assert.Equal(NetworkAccessState.Revoked, (await lab.Gateway.AuthorizeAsync(request, Ct)).State);

        var next = lab.Request(request.Association, revision: 4);
        Assert.Equal(NetworkAccessState.Authorized, (await lab.Gateway.AuthorizeAsync(next, Ct)).State);
        Assert.Equal(revoked, await lab.Gateway.RevokeAsync(revoke, Ct));
        Assert.Equal(next.GrantId, (await lab.Gateway.GetSessionAsync(next.Association.Connection, Ct)).Grant?.Id);
    }

    [Fact]
    public async Task RevocationBeforeAuthorizationFencesDelayedCommands()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate());
        Assert.Equal(NetworkAccessState.Revoked, (await lab.Gateway.RevokeAsync(lab.Revocation(request), Ct)).State);
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.AuthorizeAsync(request, Ct)).State);
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.AuthorizeAsync(
            request with { Revision = 3, OperationId = Guid.NewGuid() }, Ct)).State);
        Assert.Null((await lab.Gateway.GetSessionAsync(request.Association.Connection, Ct)).Grant);
    }

    [Fact]
    public void ReconnectionDiscardsAnUnusedReferenceFromPreviousGeneration()
    {
        var lab = new Lab();
        var previous = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var reference = lab.AssociationRequest(previous);
        var current = lab.Gateway.Reconnect(previous, TimeSpan.FromMinutes(20));
        Assert.Null(lab.Gateway.Associate(previous, reference));
        Assert.Null(lab.Gateway.Associate(current, reference));
        Assert.NotNull(lab.Gateway.Associate(current, lab.AssociationRequest(current)));
    }

    [Fact]
    public async Task ReconnectionInvalidatesOldGenerationAndAllowsNewAssociation()
    {
        var lab = new Lab();
        var observation = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
        var association = lab.Gateway.Associate(observation, lab.AssociationRequest(observation));
        Assert.NotNull(association);
        var request = lab.Request(association);
        await lab.Gateway.AuthorizeAsync(request, Ct);

        var reconnected = lab.Gateway.Reconnect(observation, TimeSpan.FromMinutes(20));
        Assert.Equal(observation.Key.ConnectionId, reconnected.Key.ConnectionId);
        Assert.Equal(observation.Key.Generation + 1, reconnected.Key.Generation);
        Assert.Equal(GatewayConnectionStatus.Missing, (await lab.Gateway.GetSessionAsync(observation.Key, Ct)).Status);
        Assert.Equal(NetworkAccessState.Revoked,
            (await lab.Gateway.GetOperationAsync(observation.Key.GatewayId, request.OperationId, Ct)).State);
        Assert.Equal(NetworkAccessState.Denied, (await lab.Gateway.AuthorizeAsync(request, Ct)).State);
        Assert.NotNull(lab.Gateway.Associate(reconnected, lab.AssociationRequest(reconnected)));
    }

    [Fact]
    public async Task CancellationBeforeExecutionDoesNotCreateGrant()
    {
        var lab = new Lab();
        var request = lab.Request(lab.Associate());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            lab.Gateway.AuthorizeAsync(request, new CancellationToken(canceled: true)));
        Assert.Null((await lab.Gateway.GetSessionAsync(request.Association.Connection, Ct)).Grant);
    }

    private sealed class Lab
    {
        public ManualClock Clock { get; } = new();
        public InMemoryCaptivePortalGateway Gateway { get; }

        public Lab() => Gateway = new InMemoryCaptivePortalGateway(Clock);

        public NetworkAssociationRequest AssociationRequest(ObservedNetworkConnection observation)
        {
            var owner = Guid.NewGuid();
            return new(Gateway.IssueAssociationReference(observation, owner, TimeSpan.FromMinutes(1)),
                Guid.NewGuid(), owner, Clock.GetUtcNow().AddMinutes(10));
        }

        public NetworkAssociation Associate(SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
        {
            var observation = Gateway.ObserveConnection(TimeSpan.FromMinutes(20), behavior);
            return Assert.IsType<NetworkAssociation>(Gateway.Associate(observation, AssociationRequest(observation)));
        }

        public NetworkAuthorizationRequest Request(NetworkAssociation association, long revision = 1) => new(
            association, Guid.NewGuid(), Guid.NewGuid(), revision,
            Clock.GetUtcNow().AddMinutes(1), Clock.GetUtcNow().AddMinutes(5));

        public NetworkRevocationRequest Revocation(NetworkAuthorizationRequest request) => new(
            request.Association.Connection, request.GrantId, Guid.NewGuid(), request.Revision + 1,
            Clock.GetUtcNow().AddMinutes(1));
    }

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delay) => _now = _now.Add(delay);
    }
}

using System.Data.Common;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.CaptivePortal;

namespace SafeNetZKP.UnitTests.UseCases.CaptivePortal;

public sealed class NetworkRevocationProcessorTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task TimedOutQueryLeavesRevocationUnresolvedAndDoesNotSendAfterBudget()
    {
        var lab = new Lab();
        var clock = new AttemptClock(lab.Clock.GetUtcNow());
        var transport = new LostReplyGateway(lab.Gateway) { OnQuery = () => clock.Elapsed() };
        var result = await new NetworkRevocationProcessor(lab.Repository, transport, clock).ProcessPendingAsync(10, Ct);
        Assert.Equal(new NetworkRevocationBatch(0, 0, 1), result);
        Assert.Equal(NetworkAccessState.Indeterminate, lab.Repository.State);
        Assert.Null(transport.Command);
    }

    [Fact]
    public async Task ConfirmationCanBeRecoveredAfterWritingTheResultFails()
    {
        var lab = new Lab();
        await lab.AuthorizeAsync();
        lab.Repository.FailWrite = true;
        await Assert.ThrowsAsync<TemporaryWriteException>(() =>
            new NetworkRevocationProcessor(lab.Repository, lab.Gateway, lab.Clock).ProcessPendingAsync(10, Ct));
        Assert.Equal(NetworkAccessState.Pending, lab.Repository.State);
        lab.Repository.FailWrite = false;

        var transport = new LostReplyGateway(lab.Gateway);
        var result = await new NetworkRevocationProcessor(lab.Repository, transport, lab.Clock)
            .ProcessPendingAsync(10, Ct);
        Assert.Equal(new NetworkRevocationBatch(1, 0, 0), result);
        Assert.Equal(NetworkAccessState.Revoked, lab.Repository.State);
        Assert.Null(transport.Command);
    }

    [Fact]
    public async Task LostReplyIsIndeterminateAndNewProcessorRecognizesGatewayConfirmation()
    {
        var lab = new Lab();
        await lab.AuthorizeAsync();
        var transport = new LostReplyGateway(lab.Gateway);
        var first = new NetworkRevocationProcessor(lab.Repository, transport, lab.Clock);
        await first.ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, lab.Repository.State);
        Assert.Equal(lab.Repository.Entry.RevocationId, transport.Command?.OperationId);
        Assert.Equal(lab.Repository.Entry.Revision + 1, transport.Command?.Revision);

        await new NetworkRevocationProcessor(lab.Repository, lab.Gateway, lab.Clock).ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Revoked, lab.Repository.State);
        var authorization = await lab.Gateway.GetOperationAsync(lab.Repository.Entry.Association.GatewayId,
            lab.Repository.Entry.Id, Ct);
        Assert.Equal(NetworkAccessState.Revoked, authorization.State);
    }

    [Fact]
    public async Task RestartedSimulatorCannotConfirmOldGrantAndExpirationEndsThePendingRequest()
    {
        var lab = new Lab();
        await lab.AuthorizeAsync();
        var restarted = new InMemoryCaptivePortalGateway(lab.Clock);
        var processor = new NetworkRevocationProcessor(lab.Repository, restarted, lab.Clock);
        await processor.ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, lab.Repository.State);

        lab.Clock.Advance(TimeSpan.FromMinutes(5));
        await processor.ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Expired, lab.Repository.State);
    }

    [Fact]
    public async Task UnrelatedConfirmationDoesNotCloseRevocation()
    {
        var lab = new Lab();
        var processor = new NetworkRevocationProcessor(lab.Repository,
            new LostReplyGateway(lab.Gateway, wrongGrant: true), lab.Clock);
        await processor.ProcessPendingAsync(10, Ct);
        Assert.Equal(NetworkAccessState.Indeterminate, lab.Repository.State);
    }

    private sealed class Lab
    {
        private readonly NetworkAuthorizationRequest _authorization;
        public ManualClock Clock { get; } = new();
        public InMemoryCaptivePortalGateway Gateway { get; }
        public PendingRepository Repository { get; }

        public Lab()
        {
            Gateway = new(Clock);
            var now = Clock.GetUtcNow();
            var observation = Gateway.ObserveConnection(TimeSpan.FromMinutes(20));
            var owner = Guid.NewGuid();
            var reference = Gateway.IssueAssociationReference(observation, owner, TimeSpan.FromMinutes(1));
            var association = Assert.IsType<NetworkAssociation>(Gateway.Associate(observation,
                new NetworkAssociationRequest(reference, Guid.NewGuid(), owner, observation.ExpiresAt)));
            _authorization = new(association, Guid.NewGuid(), Guid.NewGuid(), 1, now.AddMinutes(1), now.AddMinutes(5));
            Repository = new(new NetworkAccessEntry
            {
                Id = _authorization.OperationId, GrantId = _authorization.GrantId, Revision = _authorization.Revision,
                AccessUntil = _authorization.AccessUntil, RevocationId = Guid.NewGuid(),
                Association = new NetworkAccessAssociation
                {
                    GatewayId = observation.Key.GatewayId, ConnectionId = observation.Key.ConnectionId,
                    Generation = observation.Key.Generation
                }
            });
        }

        public async Task AuthorizeAsync() =>
            Assert.Equal(NetworkAccessState.Authorized, (await Gateway.AuthorizeAsync(_authorization, Ct)).State);
    }

    private sealed class LostReplyGateway(ICaptivePortalGateway inner, bool wrongGrant = false) : ICaptivePortalGateway
    {
        public NetworkRevocationRequest? Command { get; private set; }
        public Action? OnQuery { get; init; }

        public async Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request, CancellationToken ct)
        {
            Command = request;
            if (wrongGrant)
                return new(request.OperationId, NetworkAccessState.Revoked,
                    new NetworkAccessGrant(Guid.NewGuid(), request.Connection, NetworkAccessState.Revoked, null));

            await inner.RevokeAsync(request, ct);
            throw new TimeoutException();
        }

        public Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId, CancellationToken ct)
        {
            OnQuery?.Invoke();
            ct.ThrowIfCancellationRequested();
            return inner.GetOperationAsync(gatewayId, operationId, ct);
        }
        public Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection, CancellationToken ct) =>
            throw new NotSupportedException();
    }

    private sealed class PendingRepository(NetworkAccessEntry entry) : INetworkAccessRepository
    {
        public NetworkAccessEntry Entry { get; } = entry;
        public NetworkAccessState State { get; private set; } = NetworkAccessState.Pending;
        public bool FailWrite { get; set; }

        public Task<IReadOnlyList<NetworkAccessEntry>> ListPendingRevocationsAsync(int limit, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<NetworkAccessEntry>>(
                State is NetworkAccessState.Pending or NetworkAccessState.Indeterminate ? [Entry] : []);

        public Task RecordRevocationAsync(Guid id, Guid revocationId, NetworkAccessState state, DateTimeOffset now,
            CancellationToken ct)
        {
            Assert.Equal(Entry.Id, id);
            Assert.Equal(Entry.RevocationId, revocationId);
            if (FailWrite)
                throw new TemporaryWriteException();
            State = state;
            return Task.CompletedTask;
        }

        public Task<bool> AddAssociationAsync(NetworkAccessAssociation association, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<(NetworkAccessEntry? Entry, bool Created)> ReserveAsync(Guid associationId, Guid userId,
            byte[] sessionHash, Guid idempotencyKey, DateTimeOffset now, DateTimeOffset validUntil,
            DateTimeOffset accessUntil, CancellationToken ct) => throw new NotSupportedException();
        public Task<NetworkAccessEntry?> FindOwnedAsync(Guid operationId, Guid userId, byte[] sessionHash,
            CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<NetworkAccessEntry>> ListOwnedAsync(Guid userId, byte[] sessionHash, int limit,
            CancellationToken ct) => throw new NotSupportedException();
        public Task RecordAuthorizationAsync(Guid id, NetworkAccessState state, DateTimeOffset? confirmedUntil,
            DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> QueueRevocationAsync(Guid id, Guid userId, byte[] sessionHash, DateTimeOffset now,
            CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class TemporaryWriteException : DbException;

    private sealed class AttemptClock(DateTimeOffset now) : TimeProvider
    {
        public Action Elapsed { get; private set; } = null!;
        public override DateTimeOffset GetUtcNow() => now;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Assert.Equal(TimeSpan.FromSeconds(2), dueTime);
            Elapsed = () => callback(state);
            return new OneShotTimer();
        }

        private sealed class OneShotTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan delay) => _now = _now.Add(delay);
    }
}

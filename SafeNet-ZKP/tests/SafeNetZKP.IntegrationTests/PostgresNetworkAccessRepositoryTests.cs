using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.CaptivePortal;
using SafeNetZKP.Infrastructure.Persistence;
using SafeNetZKP.Infrastructure.Repositories;

namespace SafeNetZKP.IntegrationTests;

public sealed class PostgresNetworkAccessRepositoryTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task OwnershipAndConcurrentIdempotencySurviveNewDatabaseContext()
    {
        await using var lab = new Lab();
        await using var first = lab.Open();
        var (owner, _) = await lab.SignInAsync(first);
        var (otherSession, _) = await lab.SignInAsync(first, owner.UserId);
        var (otherUser, _) = await lab.SignInAsync(first);
        var binding = await lab.AssociateAsync(first, owner);
        var otherBinding = await lab.AssociateAsync(first, otherSession);
        var key = Guid.NewGuid();

        await using var second = lab.Open();
        var results = await Task.WhenAll(lab.AuthorizeAsync(first, owner, binding, key),
            lab.AuthorizeAsync(second, owner, binding, key));
        Assert.Equal(results[0]?.OperationId, results[1]?.OperationId);
        var id = Assert.IsType<GatewayOperationResult>(results[0]).OperationId;
        var deviceB = Assert.IsType<GatewayOperationResult>(
            await lab.AuthorizeAsync(first, otherSession, otherBinding, Guid.NewGuid()));
        Assert.NotEqual(id, deviceB.OperationId);

        await using var restarted = lab.Open();
        Assert.Equal(1, await restarted.Db.NetworkAccessOperations.CountAsync(entry => entry.AssociationId == binding.Id));
        var row = await restarted.Db.NetworkAccessOperations.Include(entry => entry.Association)
            .SingleAsync(entry => entry.Id == id);
        Assert.Equal(Hash(owner.Identifier), row.Association.SessionHash);
        Assert.Equal(owner.UserId, row.Association.UserId);
        Assert.Equal(key, row.IdempotencyKey);
        Assert.Equal(1, row.Revision);
        Assert.Equal(NetworkAccessState.Authorized,
            (await restarted.Access.GetOperationAsync(owner.Context, id, Ct))?.State);
        Assert.Null(await restarted.Access.GetOperationAsync(otherSession.Context, id, Ct));
        Assert.Null(await restarted.Access.RequestRevocationAsync(otherUser.Context, id, Ct));
        Assert.Equal(NetworkAccessState.Authorized,
            (await restarted.Access.GetOperationAsync(otherSession.Context, deviceB.OperationId, Ct))?.State);
    }

    [Fact]
    public async Task LogoutQueuesEachGrantAtomicallyAndReconcilesWithoutActiveWebSession()
    {
        await using var lab = new Lab();
        await using var first = lab.Open();
        var (owner, _) = await lab.SignInAsync(first);
        var (otherSession, _) = await lab.SignInAsync(first, owner.UserId);
        var binding = await lab.AssociateAsync(first, owner, SimulatedAuthorizationBehavior.TimeoutAfterApplying);
        var otherBinding = await lab.AssociateAsync(first, otherSession);
        var possiblyApplied = Assert.IsType<GatewayOperationResult>(
            await lab.AuthorizeAsync(first, owner, binding, Guid.NewGuid()));
        var independent = Assert.IsType<GatewayOperationResult>(
            await lab.AuthorizeAsync(first, otherSession, otherBinding, Guid.NewGuid()));
        Assert.Equal(NetworkAccessState.Indeterminate, possiblyApplied.State);

        await first.Sessions.RevokeAsync(owner.Identifier, owner.UserId, Ct);
        Assert.False(await first.Sessions.IsActiveAsync(owner.Identifier, owner.UserId, Ct));
        Assert.Null(await lab.AuthorizeAsync(first, owner, binding, Guid.NewGuid()));
        var observation = lab.Gateway.ObserveConnection(TimeSpan.FromMinutes(15));
        var reference = lab.Gateway.IssueAssociationReference(observation, TimeSpan.FromMinutes(1));
        Assert.Null(await first.Access.AssociateAsync(owner.Context, observation, reference, Ct));

        await using var restarted = lab.Open();
        var queued = await restarted.Db.NetworkAccessOperations.AsNoTracking()
            .SingleAsync(entry => entry.Id == possiblyApplied.OperationId);
        Assert.NotNull(queued.RevocationId);
        Assert.Equal(NetworkAccessState.Pending, queued.RevocationState);
        // Uma confirmação que chegou depois do logout não pode substituir a revogação pendente.
        await restarted.Repository.RecordAuthorizationAsync(queued.Id, NetworkAccessState.Authorized,
            queued.AccessUntil, lab.Clock.GetUtcNow(), Ct);
        var unavailable = new NetworkRevocationProcessor(restarted.Repository, new UnavailableGateway(), lab.Clock);
        await unavailable.ProcessPendingAsync(32, Ct);
        var unresolved = await restarted.Db.NetworkAccessOperations.AsNoTracking().SingleAsync(entry => entry.Id == queued.Id);
        Assert.Equal(NetworkAccessState.Indeterminate, unresolved.RevocationState);
        Assert.Equal(NetworkAccessState.Indeterminate, unresolved.State);

        var recovered = new NetworkRevocationProcessor(restarted.Repository, lab.Gateway, lab.Clock);
        await recovered.ProcessPendingAsync(32, Ct);
        await recovered.ProcessPendingAsync(32, Ct);
        var finished = await restarted.Db.NetworkAccessOperations.AsNoTracking().SingleAsync(entry => entry.Id == queued.Id);
        Assert.Equal(NetworkAccessState.Revoked, finished.RevocationState);
        Assert.Equal(queued.RevocationId, finished.RevocationId);
        Assert.Equal(NetworkAccessState.Authorized,
            (await restarted.Access.GetOperationAsync(otherSession.Context, independent.OperationId, Ct))?.State);
    }

    [Fact]
    public async Task ExpiredSessionCannotReserveAccessAndExplicitRevocationIsIdempotent()
    {
        await using var lab = new Lab();
        await using var scope = lab.Open();
        var (caller, expiration) = await lab.SignInAsync(scope);
        var binding = await lab.AssociateAsync(scope, caller);
        var result = Assert.IsType<GatewayOperationResult>(
            await lab.AuthorizeAsync(scope, caller, binding, Guid.NewGuid()));
        Assert.Equal(NetworkAccessState.Pending,
            (await scope.Access.RequestRevocationAsync(caller.Context, result.OperationId, Ct))?.State);
        var before = await scope.Db.NetworkAccessOperations.AsNoTracking().SingleAsync(entry => entry.Id == result.OperationId);
        Assert.Equal(NetworkAccessState.Pending,
            (await scope.Access.RequestRevocationAsync(caller.Context, result.OperationId, Ct))?.State);
        var after = await scope.Db.NetworkAccessOperations.AsNoTracking().SingleAsync(entry => entry.Id == result.OperationId);
        Assert.Equal(before.RevocationId, after.RevocationId);

        lab.Clock.AdvanceTo(expiration);
        Assert.Null(await lab.AuthorizeAsync(scope, caller, binding, Guid.NewGuid()));
        var processor = new NetworkRevocationProcessor(scope.Repository, lab.Gateway, lab.Clock);
        await processor.ProcessPendingAsync(32, Ct);
        Assert.Equal(NetworkAccessState.Expired, (await scope.Db.NetworkAccessOperations.AsNoTracking()
            .SingleAsync(entry => entry.Id == result.OperationId)).RevocationState);
    }

    private static byte[] Hash(string identifier) => SHA256.HashData(Convert.FromHexString(identifier));

    private sealed class Lab : IAsyncDisposable
    {
        private readonly List<Guid> _users = [];
        public ManualClock Clock { get; } = new();
        public InMemoryCaptivePortalGateway Gateway { get; }

        public Lab() => Gateway = new InMemoryCaptivePortalGateway(Clock);

        public Scope Open() => new(TestDatabase.CreateContext(), Gateway, Clock);

        public async Task<(Caller Caller, DateTimeOffset ExpiresAt)> SignInAsync(Scope scope, Guid? existingUser = null)
        {
            var userId = existingUser ?? await CreateUserAsync(scope);
            var ticket = await scope.Sessions.CreateAsync(userId, Ct);
            return (new Caller(userId, ticket.Id), ticket.ExpiresAt);
        }

        private async Task<Guid> CreateUserAsync(Scope scope)
        {
            var user = new User("Network access integration test");
            await new PostgresUserRepository(scope.Db).AddAsync(user);
            _users.Add(user.Id);
            return user.Id;
        }

        public async Task<PersistentNetworkAccessBinding> AssociateAsync(Scope scope, Caller caller,
            SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
        {
            var observation = Gateway.ObserveConnection(TimeSpan.FromMinutes(30), behavior);
            var reference = Gateway.IssueAssociationReference(observation, TimeSpan.FromMinutes(1));
            return Assert.IsType<PersistentNetworkAccessBinding>(
                await scope.Access.AssociateAsync(caller.Context, observation, reference, Ct));
        }

        public Task<GatewayOperationResult?> AuthorizeAsync(Scope scope, Caller caller, PersistentNetworkAccessBinding binding,
            Guid key) => scope.Access.AuthorizeAsync(caller.Context, binding, key,
                TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), Ct);

        public async ValueTask DisposeAsync()
        {
            if (_users.Count == 0)
                return;

            await using var cleanup = TestDatabase.CreateContext();
            await cleanup.NetworkAccessOperations.Where(item => _users.Contains(item.Association.UserId)).ExecuteDeleteAsync();
            await cleanup.NetworkAccessAssociations.Where(item => _users.Contains(item.UserId)).ExecuteDeleteAsync();
            await cleanup.Users.Where(user => _users.Contains(user.Id)).ExecuteDeleteAsync();
        }
    }

    private sealed class Scope : IAsyncDisposable
    {
        public SafeNetZkpDbContext Db { get; }
        public AuthenticatedSessionService Sessions { get; }
        public PostgresNetworkAccessRepository Repository { get; }
        public PersistentNetworkAccessService Access { get; }

        public Scope(SafeNetZkpDbContext db, InMemoryCaptivePortalGateway gateway, TimeProvider clock)
        {
            Db = db;
            Sessions = new(new PostgresAuthenticatedSessionRepository(db), clock);
            Repository = new(db);
            Access = new(new NetworkAccessService(Sessions, gateway, gateway, clock), Sessions, Repository, clock);
        }

        public ValueTask DisposeAsync() => Db.DisposeAsync();
    }

    private sealed class Caller(Guid userId, string identifier)
    {
        public Guid UserId { get; } = userId;
        public string Identifier { get; } = identifier;
        public NetworkAccessCaller Context { get; } = new(new CurrentUser(userId), identifier);
    }

    private sealed class CurrentUser(Guid id) : ICurrentUserContext
    {
        public Guid? UserId => id;
    }

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void AdvanceTo(DateTimeOffset value) => _now = value;
    }

    private sealed class UnavailableGateway : ICaptivePortalGateway
    {
        public Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId, CancellationToken ct) =>
            throw new GatewayCommunicationException();
        public Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request, CancellationToken ct) =>
            throw new NotSupportedException();
        public Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection, CancellationToken ct) =>
            throw new NotSupportedException();
    }
}

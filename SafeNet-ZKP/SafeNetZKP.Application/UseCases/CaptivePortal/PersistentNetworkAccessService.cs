using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.UseCases.CaptivePortal;

public sealed class PersistentNetworkAccessBinding
{
    internal PersistentNetworkAccessBinding(Guid id, NetworkAccessBinding verified)
    {
        Id = id;
        Verified = verified;
    }

    public Guid Id { get; }
    public DateTimeOffset ExpiresAt => Verified.Association.ExpiresAt;
    internal NetworkAccessBinding Verified { get; }
}

public sealed record NetworkGrantSummary(Guid OperationId, NetworkAccessState LastKnownState,
    DateTimeOffset AccessUntil);

public sealed class PersistentNetworkAccessService(
    NetworkAccessService access,
    AuthenticatedSessionService sessions,
    INetworkAccessRepository repository,
    TimeProvider clock)
{
    public async Task<PersistentNetworkAccessBinding?> AssociateAsync(NetworkAccessCaller caller,
        ObservedNetworkConnection observation, string reference, CancellationToken ct)
    {
        var binding = await access.AssociateAsync(caller, observation, reference, ct);
        if (binding is null || await ResolveOwnerAsync(caller, ct) is not { } owner ||
            owner.UserId != binding.Association.UserId ||
            owner.Reference != binding.Association.AuthenticatedSessionReference)
            return null;

        var association = new NetworkAccessAssociation
        {
            Id = Guid.NewGuid(), GatewayId = observation.Key.GatewayId,
            ConnectionId = observation.Key.ConnectionId, Generation = observation.Key.Generation,
            UserId = owner.UserId, SessionHash = owner.Hash, CreatedAt = clock.GetUtcNow(),
            ExpiresAt = binding.Association.ExpiresAt
        };
        return await repository.AddAssociationAsync(association, ct)
            ? new PersistentNetworkAccessBinding(association.Id, binding) : null;
    }

    public async Task<GatewayOperationResult?> AuthorizeAsync(NetworkAccessCaller caller,
        PersistentNetworkAccessBinding binding, Guid idempotencyKey, TimeSpan requestLifetime,
        TimeSpan accessLifetime, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(idempotencyKey, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(requestLifetime, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(accessLifetime, TimeSpan.Zero);
        if (await ResolveOwnerAsync(caller, ct) is not { } owner)
            return null;

        var now = clock.GetUtcNow();
        var accessUntil = Earlier(now.Add(accessLifetime), binding.Verified.Association.ExpiresAt);
        var (entry, created) = await repository.ReserveAsync(binding.Id, owner.UserId, owner.Hash, idempotencyKey,
            now, Earlier(now.Add(requestLifetime), accessUntil), accessUntil, ct);
        if (entry is null)
            return null;

        if (!created)
        {
            if (ClosedOrRevoking(entry, clock.GetUtcNow()) is { } closed)
                return closed;
            if (entry.State == NetworkAccessState.Authorized || entry.GrantState == NetworkAccessState.Authorized ||
                entry.ValidUntil <= clock.GetUtcNow())
                return await GetOperationAsync(caller, entry.Id, ct);
        }

        var command = ToAuthorization(entry, binding.Verified.Association);
        var result = await access.AuthorizeAsync(caller, command, ct);
        return await SaveAndReadAsync(caller, entry, owner, result, ct);
    }

    public async Task<GatewayOperationResult?> GetOperationAsync(NetworkAccessCaller caller, Guid operationId,
        CancellationToken ct)
    {
        if (await ResolveOwnerAsync(caller, ct) is not { } owner ||
            await repository.FindOwnedAsync(operationId, owner.UserId, owner.Hash, ct) is not { } entry)
            return null;

        if (ClosedOrRevoking(entry, clock.GetUtcNow()) is { } closed)
            return closed;

        var binding = new NetworkAssociation(entry.Association.Connection, owner.UserId, owner.Reference,
            entry.Association.ExpiresAt);
        var result = await access.GetOperationAsync(caller, ToAuthorization(entry, binding), ct);
        return await SaveAndReadAsync(caller, entry, owner, result, ct);
    }

    public async Task<GatewayOperationResult?> RequestRevocationAsync(NetworkAccessCaller caller, Guid operationId,
        CancellationToken ct)
    {
        if (await ResolveOwnerAsync(caller, ct) is not { } owner ||
            !await repository.QueueRevocationAsync(operationId, owner.UserId, owner.Hash, clock.GetUtcNow(), ct) ||
            await repository.FindOwnedAsync(operationId, owner.UserId, owner.Hash, ct) is not { } entry)
            return null;

        return ClosedOrRevoking(entry, clock.GetUtcNow());
    }

    public async Task<IReadOnlyList<NetworkGrantSummary>?> ListGrantsAsync(NetworkAccessCaller caller,
        CancellationToken ct)
    {
        if (await ResolveOwnerAsync(caller, ct) is not { } owner)
            return null;

        var entries = await repository.ListOwnedAsync(owner.UserId, owner.Hash, 50, ct);
        var now = clock.GetUtcNow();
        return entries.Select(entry => new NetworkGrantSummary(entry.Id,
            ClosedOrRevoking(entry, now)?.State ?? entry.State, entry.AccessUntil)).ToArray();
    }

    private async Task<GatewayOperationResult?> SaveAndReadAsync(NetworkAccessCaller caller, NetworkAccessEntry entry,
        SessionOwner owner, GatewayOperationResult result, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        await repository.RecordAuthorizationAsync(entry.Id, result.State, result.Grant?.ExpiresAt, now, ct);
        if (await ResolveOwnerAsync(caller, ct) is not { } current || current.UserId != owner.UserId ||
            !current.Hash.AsSpan().SequenceEqual(owner.Hash) ||
            await repository.FindOwnedAsync(entry.Id, owner.UserId, owner.Hash, ct) is not { } persisted)
            return null;

        if (ClosedOrRevoking(persisted, clock.GetUtcNow()) is { } closed)
            return closed;

        if (result.State == NetworkAccessState.Authorized && persisted.State == NetworkAccessState.Authorized &&
            persisted.ConfirmedUntil > clock.GetUtcNow())
            return result;

        return new(entry.Id, result.State == NetworkAccessState.Pending && persisted.State == NetworkAccessState.Pending
            ? NetworkAccessState.Pending : NetworkAccessState.Indeterminate);
    }

    private async Task<SessionOwner?> ResolveOwnerAsync(NetworkAccessCaller caller, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (caller.User.UserId is not { } userId || userId == Guid.Empty ||
            await sessions.ResolveActiveAsync(caller.SessionIdentifier, userId, ct) is not { } active)
            return null;

        return new SessionOwner(userId, active.Reference, active.Hash);
    }

    private static GatewayOperationResult? ClosedOrRevoking(NetworkAccessEntry entry, DateTimeOffset now)
    {
        var state = entry.AccessUntil <= now && entry.RevocationState != NetworkAccessState.Revoked
            ? NetworkAccessState.Expired : entry.RevocationState ?? entry.State;
        return entry.RevocationId is not null || state is NetworkAccessState.Denied or NetworkAccessState.Expired
            or NetworkAccessState.Revoked ? new GatewayOperationResult(entry.Id, state) : null;
    }

    private static NetworkAccessAuthorization ToAuthorization(NetworkAccessEntry entry, NetworkAssociation association) =>
        new(new NetworkAuthorizationRequest(association, entry.GrantId, entry.Id, entry.Revision,
            entry.ValidUntil, entry.AccessUntil));

    private static DateTimeOffset Earlier(DateTimeOffset first, DateTimeOffset second) => first < second ? first : second;

    private sealed record SessionOwner(Guid UserId, Guid Reference, byte[] Hash);
}

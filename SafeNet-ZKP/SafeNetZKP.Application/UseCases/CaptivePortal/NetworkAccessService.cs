using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.UseCases.CaptivePortal;

public sealed class NetworkAccessService(
    AuthenticatedSessionService sessions,
    ICaptivePortalAssociationGateway associations,
    ICaptivePortalGateway gateway,
    TimeProvider clock)
{
    public async Task<NetworkAccessBinding?> AssociateAsync(NetworkAccessCaller caller,
        ObservedNetworkConnection observation, string reference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (caller.User.UserId is not { } userId || userId == Guid.Empty)
            return null;

        var session = await sessions.ResolveActiveAsync(caller.SessionIdentifier, userId, cancellationToken);
        if (session is not { } active)
            return null;

        var request = new NetworkAssociationRequest(reference, userId, active.Reference, active.ExpiresAt);
        var association = await associations.AssociateAsync(observation, request, cancellationToken);
        if (association is null || association.Connection != observation.Key || association.UserId != userId ||
            association.AuthenticatedSessionReference != active.Reference ||
            association.ExpiresAt > active.ExpiresAt || association.ExpiresAt > observation.ExpiresAt)
            return null;

        return await OwnsActiveBindingAsync(caller, association, cancellationToken)
            ? new NetworkAccessBinding(association) : null;
    }

    public NetworkAccessAuthorization PrepareAuthorization(NetworkAccessBinding binding, long revision,
        TimeSpan requestLifetime, TimeSpan accessLifetime)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(revision);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(requestLifetime, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(accessLifetime, TimeSpan.Zero);
        var now = clock.GetUtcNow();
        var association = binding.Association;
        return new NetworkAccessAuthorization(new NetworkAuthorizationRequest(
            association, Guid.NewGuid(), Guid.NewGuid(), revision,
            Earlier(now.Add(requestLifetime), association.ExpiresAt),
            Earlier(now.Add(accessLifetime), association.ExpiresAt)));
    }

    public NetworkAccessRevocation PrepareRevocation(NetworkAccessAuthorization authorization, long revision,
        TimeSpan requestLifetime)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(revision, authorization.Request.Revision);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(requestLifetime, TimeSpan.Zero);
        var association = authorization.Association;
        return new NetworkAccessRevocation(association, new NetworkRevocationRequest(
            association.Connection, authorization.GrantId, Guid.NewGuid(), revision,
            Earlier(clock.GetUtcNow().Add(requestLifetime), association.ExpiresAt)));
    }

    public Task<GatewayOperationResult> AuthorizeAsync(NetworkAccessCaller caller,
        NetworkAccessAuthorization operation, CancellationToken cancellationToken) =>
        ExecuteAsync(caller, operation, ct => clock.GetUtcNow() < operation.Request.ValidUntil
            ? gateway.AuthorizeAsync(operation.Request, ct) : QueryAsync(operation, ct), cancellationToken);

    public Task<GatewayOperationResult> GetOperationAsync(NetworkAccessCaller caller,
        NetworkAccessOperation operation, CancellationToken cancellationToken) =>
        ExecuteAsync(caller, operation, ct => QueryAsync(operation, ct), cancellationToken);

    public Task<GatewayOperationResult> RevokeAsync(NetworkAccessCaller caller,
        NetworkAccessRevocation operation, CancellationToken cancellationToken) =>
        ExecuteAsync(caller, operation, ct => clock.GetUtcNow() < operation.Request.ValidUntil
            ? gateway.RevokeAsync(operation.Request, ct) : QueryAsync(operation, ct), cancellationToken);

    private Task<GatewayOperationResult> QueryAsync(NetworkAccessOperation operation, CancellationToken cancellationToken) =>
        gateway.GetOperationAsync(operation.Association.Connection.GatewayId, operation.Id, cancellationToken);

    private async Task<GatewayOperationResult> ExecuteAsync(NetworkAccessCaller caller, NetworkAccessOperation operation,
        Func<CancellationToken, Task<GatewayOperationResult>> send, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await OwnsActiveBindingAsync(caller, operation.Association, cancellationToken))
            return new(operation.Id, NetworkAccessState.Denied);

        GatewayOperationResult result;
        try
        {
            result = await send(cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested &&
            exception is GatewayCommunicationException or TimeoutException or OperationCanceledException)
        {
            return new(operation.Id, NetworkAccessState.Indeterminate);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (result.OperationId != operation.Id ||
            (result.Grant is { } grant &&
                (grant.Id != operation.GrantId || grant.Connection != operation.Association.Connection ||
                    grant.State != result.State)))
            return new(operation.Id, NetworkAccessState.Indeterminate);

        if (result.State == NetworkAccessState.Authorized)
        {
            if (operation is not NetworkAccessAuthorization authorization ||
                result.Grant?.ExpiresAt is not { } expiresAt || expiresAt > authorization.Request.AccessUntil)
                return new(operation.Id, NetworkAccessState.Indeterminate);

            if (expiresAt <= clock.GetUtcNow())
                return new(operation.Id, NetworkAccessState.Expired);

            // A sessão pode ter sido revogada enquanto o gateway processava o comando.
            if (!await OwnsActiveBindingAsync(caller, operation.Association, cancellationToken))
                return new(operation.Id, NetworkAccessState.Denied);
            if (expiresAt <= clock.GetUtcNow())
                return new(operation.Id, NetworkAccessState.Expired);
        }

        if (result.State is NetworkAccessState.Pending or NetworkAccessState.Indeterminate or NetworkAccessState.Denied)
            return new(operation.Id, result.State);

        return result.Grant is not null ? result : new(operation.Id, NetworkAccessState.Indeterminate);
    }

    private async Task<bool> OwnsActiveBindingAsync(NetworkAccessCaller caller, NetworkAssociation association,
        CancellationToken cancellationToken)
    {
        if (caller.User.UserId != association.UserId || association.ExpiresAt <= clock.GetUtcNow())
            return false;

        var session = await sessions.ResolveActiveAsync(caller.SessionIdentifier, association.UserId, cancellationToken);
        return session is { } active && active.Reference == association.AuthenticatedSessionReference &&
            association.ExpiresAt > clock.GetUtcNow() && active.ExpiresAt >= association.ExpiresAt;
    }

    private static DateTimeOffset Earlier(DateTimeOffset first, DateTimeOffset second) => first < second ? first : second;
}

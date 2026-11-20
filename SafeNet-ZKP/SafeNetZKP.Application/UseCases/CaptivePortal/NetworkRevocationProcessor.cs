using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.UseCases.CaptivePortal;

public sealed class NetworkRevocationProcessor(INetworkAccessRepository repository, ICaptivePortalGateway gateway,
    TimeProvider clock)
{
    public async Task ProcessPendingAsync(int batchSize, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(batchSize);
        foreach (var entry in await repository.ListPendingRevocationsAsync(batchSize, ct))
        {
            ct.ThrowIfCancellationRequested();
            var id = entry.RevocationId!.Value;
            var state = entry.AccessUntil <= clock.GetUtcNow() ? NetworkAccessState.Expired
                : await TryRevokeAsync(entry, id, ct);
            await repository.RecordRevocationAsync(entry.Id, id, state, clock.GetUtcNow(), ct);
        }
    }

    private async Task<NetworkAccessState> TryRevokeAsync(NetworkAccessEntry entry, Guid id, CancellationToken ct)
    {
        var connection = entry.Association.Connection;
        try
        {
            var status = await gateway.GetOperationAsync(connection.GatewayId, id, ct);
            if (Confirmed(status, entry, id))
                return status.State;

            if (entry.AccessUntil <= clock.GetUtcNow())
                return NetworkAccessState.Expired;

            var result = await gateway.RevokeAsync(new NetworkRevocationRequest(connection, entry.GrantId,
                id, checked(entry.Revision + 1), entry.AccessUntil), ct);
            return Confirmed(result, entry, id) ? result.State : NetworkAccessState.Indeterminate;
        }
        catch (Exception exception) when (!ct.IsCancellationRequested &&
            exception is GatewayCommunicationException or TimeoutException or OperationCanceledException)
        {
            return NetworkAccessState.Indeterminate;
        }
    }

    private static bool Confirmed(GatewayOperationResult result, NetworkAccessEntry entry, Guid id) =>
        result.OperationId == id && result.State is NetworkAccessState.Revoked or NetworkAccessState.Expired &&
        result.Grant is { } grant && grant.State == result.State &&
        grant.Id == entry.GrantId && grant.Connection == entry.Association.Connection;
}

using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.Interfaces.Gateways;

public interface ICaptivePortalGateway
{
    Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection, CancellationToken cancellationToken);
    Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request, CancellationToken cancellationToken);
    Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId, CancellationToken cancellationToken);
    Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request, CancellationToken cancellationToken);
}

public enum GatewayConnectionStatus
{
    Observed,
    Missing,
    Indeterminate
}

public sealed record GatewayConnectionResult(
    GatewayConnectionStatus Status, ObservedNetworkConnection? Connection = null, NetworkAccessGrant? Grant = null);

public sealed record NetworkAuthorizationRequest(
    NetworkAssociation Association,
    Guid GrantId,
    Guid OperationId,
    long Revision,
    DateTimeOffset ValidUntil,
    DateTimeOffset AccessUntil);

public sealed record NetworkRevocationRequest(
    NetworkConnectionKey Connection,
    Guid GrantId,
    Guid OperationId,
    long Revision,
    DateTimeOffset ValidUntil);

// Authorized só representa acesso quando confirmado para a concessão indicada.
// Pending e Indeterminate exigem nova consulta antes de anunciar acesso.
public sealed record GatewayOperationResult(
    Guid OperationId, NetworkAccessState State, NetworkAccessGrant? Grant = null);

namespace SafeNetZKP.Domain.CaptivePortal;

public sealed record NetworkConnectionKey(Guid GatewayId, Guid ConnectionId, long Generation);

public sealed record ObservedNetworkConnection(NetworkConnectionKey Key, DateTimeOffset ExpiresAt);

public sealed record NetworkAssociationRequest(
    string Reference,
    Guid UserId,
    Guid AuthenticatedSessionReference,
    DateTimeOffset AuthenticatedSessionExpiresAt);

// Contexto interno da aplicação. O adaptador real deve extrair apenas os dados de rede.
public sealed record NetworkAssociation(
    NetworkConnectionKey Connection,
    Guid UserId,
    Guid AuthenticatedSessionReference,
    DateTimeOffset ExpiresAt);

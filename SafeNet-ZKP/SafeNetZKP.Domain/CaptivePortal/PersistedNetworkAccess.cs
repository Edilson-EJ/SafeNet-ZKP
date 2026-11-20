namespace SafeNetZKP.Domain.CaptivePortal;

public sealed class NetworkAccessAssociation
{
    public Guid Id { get; init; }
    public Guid GatewayId { get; init; }
    public Guid ConnectionId { get; init; }
    public long Generation { get; init; }
    public Guid UserId { get; init; }
    public byte[] SessionHash { get; init; } = [];
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public long LastRevision { get; init; }

    public NetworkConnectionKey Connection => new(GatewayId, ConnectionId, Generation);
}

// A mesma linha guarda a autorização e a intenção durável de revogar sua concessão.
public sealed class NetworkAccessEntry
{
    public Guid Id { get; init; }
    public Guid AssociationId { get; init; }
    public NetworkAccessAssociation Association { get; init; } = null!;
    public Guid IdempotencyKey { get; init; }
    public Guid GrantId { get; init; }
    public long Revision { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public DateTimeOffset ValidUntil { get; init; }
    public DateTimeOffset AccessUntil { get; init; }
    public NetworkAccessState State { get; init; }
    public NetworkAccessState? GrantState { get; init; }
    public DateTimeOffset? ConfirmedUntil { get; init; }
    public Guid? RevocationId { get; init; }
    public NetworkAccessState? RevocationState { get; init; }
    public DateTimeOffset? RevocationQueuedAt { get; init; }
}

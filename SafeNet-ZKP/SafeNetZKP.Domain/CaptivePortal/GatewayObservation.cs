namespace SafeNetZKP.Domain.CaptivePortal;

// Authenticated gateway report. It carries no browser binding or association capability.
public sealed record GatewayObservation(Guid GatewayId, string Nonce, Guid ConnectionId,
    long Generation, DateTimeOffset ObservedAt, DateTimeOffset ExpiresAt);

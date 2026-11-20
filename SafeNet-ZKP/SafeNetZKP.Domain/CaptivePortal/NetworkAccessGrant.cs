namespace SafeNetZKP.Domain.CaptivePortal;

public enum NetworkAccessState
{
    Pending,
    Authorized,
    Denied,
    Indeterminate,
    Expired,
    Revoked
}

public sealed record NetworkAccessGrant(
    Guid Id, NetworkConnectionKey Connection, NetworkAccessState State, DateTimeOffset? ExpiresAt);

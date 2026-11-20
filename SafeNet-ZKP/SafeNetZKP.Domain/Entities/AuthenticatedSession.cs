namespace SafeNetZKP.Domain.Entities;

public sealed class AuthenticatedSession(
    byte[] idHash, Guid userId, DateTime createdAt, DateTime expiresAt)
{
    public byte[] IdHash { get; private set; } = idHash;
    public Guid UserId { get; private set; } = userId;
    public DateTime CreatedAt { get; private set; } = createdAt;
    public DateTime ExpiresAt { get; private set; } = expiresAt;
    public DateTime? RevokedAt { get; private set; }
}

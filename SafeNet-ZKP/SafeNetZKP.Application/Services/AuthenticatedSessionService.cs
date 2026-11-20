using System.Security.Cryptography;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.Services;

public sealed class AuthenticatedSessionService(
    IAuthenticatedSessionRepository repository, TimeProvider clock)
{
    public static TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(20);

    public async Task<(string Id, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt)> CreateAsync(
        Guid userId, CancellationToken cancellationToken)
    {
        var id = RandomNumberGenerator.GetBytes(32);
        var createdAt = clock.GetUtcNow();
        var expiresAt = createdAt.Add(Lifetime);
        await repository.AddAsync(new AuthenticatedSession(
            SHA256.HashData(id), userId, createdAt.UtcDateTime, expiresAt.UtcDateTime), cancellationToken);
        return (Convert.ToHexString(id), createdAt, expiresAt);
    }

    public Task<bool> IsActiveAsync(string id, Guid userId, CancellationToken cancellationToken) =>
        repository.IsActiveAsync(SHA256.HashData(Convert.FromHexString(id)), userId,
            clock.GetUtcNow().UtcDateTime, cancellationToken);

    public Task RevokeAsync(string id, Guid userId, CancellationToken cancellationToken) =>
        repository.RevokeAsync(SHA256.HashData(Convert.FromHexString(id)), userId,
            clock.GetUtcNow().UtcDateTime, cancellationToken);
}

using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.Infrastructure.Repositories;

public sealed class PostgresAuthenticatedSessionRepository(SafeNetZkpDbContext dbContext)
    : IAuthenticatedSessionRepository
{
    public async Task AddAsync(AuthenticatedSession session, CancellationToken cancellationToken)
    {
        dbContext.AuthenticatedSessions.Add(session);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public Task<bool> IsActiveAsync(
        byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken) =>
        dbContext.AuthenticatedSessions.AnyAsync(session =>
            session.IdHash == idHash && session.UserId == userId &&
            session.RevokedAt == null && session.ExpiresAt > now, cancellationToken);

    public async Task RevokeAsync(
        byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken)
    {
        await dbContext.AuthenticatedSessions
            .Where(session => session.IdHash == idHash && session.UserId == userId && session.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(session => session.RevokedAt, (DateTime?)now),
                cancellationToken);
    }
}

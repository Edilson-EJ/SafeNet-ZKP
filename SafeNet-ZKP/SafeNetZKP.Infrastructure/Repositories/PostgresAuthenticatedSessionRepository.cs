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
        ActiveSessions(idHash, userId, now).AnyAsync(cancellationToken);

    public Task<DateTime?> GetActiveExpirationAsync(byte[] idHash, Guid userId, DateTime now,
        CancellationToken cancellationToken) =>
        ActiveSessions(idHash, userId, now).Select(session => (DateTime?)session.ExpiresAt)
            .SingleOrDefaultAsync(cancellationToken);

    private IQueryable<AuthenticatedSession> ActiveSessions(byte[] idHash, Guid userId, DateTime now) =>
        dbContext.AuthenticatedSessions.Where(session => session.IdHash == idHash &&
            session.UserId == userId && session.RevokedAt == null && session.ExpiresAt > now);

    public async Task RevokeAsync(
        byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        var revoked = await dbContext.AuthenticatedSessions
            .Where(session => session.IdHash == idHash && session.UserId == userId && session.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(session => session.RevokedAt, (DateTime?)now),
                cancellationToken);
        if (revoked != 0)
            await new PostgresNetworkAccessRepository(dbContext).QueueSessionRevocationsAsync(
                userId, idHash, new DateTimeOffset(now, TimeSpan.Zero), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }
}

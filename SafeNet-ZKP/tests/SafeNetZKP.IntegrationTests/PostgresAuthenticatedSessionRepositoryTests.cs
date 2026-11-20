using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Repositories;

namespace SafeNetZKP.IntegrationTests;

public sealed class PostgresAuthenticatedSessionRepositoryTests
{
    [Fact]
    public async Task AuthenticatedSessionsSchema_MatchesMigrationInIsolatedDatabase()
    {
        await using var context = TestDatabase.CreateContext();
        Assert.Equal("safenet_zkp_test", await context.Database
            .SqlQueryRaw<string>("SELECT current_database()::text AS \"Value\"").SingleAsync());

        var constraints = await context.Database.SqlQueryRaw<string>("""
            SELECT conname::text AS "Value"
            FROM pg_constraint
            WHERE conrelid = '"AuthenticatedSessions"'::regclass
            """).ToListAsync();
        Assert.Contains("PK_AuthenticatedSessions", constraints);
        Assert.Contains("FK_AuthenticatedSessions_Users_UserId", constraints);
        Assert.Contains("CK_AuthenticatedSessions_IdHashLength", constraints);
        Assert.Contains("CK_AuthenticatedSessions_Expiration", constraints);

        var indexes = await context.Database.SqlQueryRaw<string>("""
            SELECT indexname::text AS "Value"
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'AuthenticatedSessions'
            """).ToListAsync();
        Assert.Contains("PK_AuthenticatedSessions", indexes);
        Assert.Contains("IX_AuthenticatedSessions_UserId", indexes);
        Assert.Contains("IX_AuthenticatedSessions_ExpiresAt", indexes);
    }

    [Fact]
    public async Task Sessions_ArePersistedAndRevokedIndependently()
    {
        var user = new User("Session repository test");
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()).UtcDateTime;
        var first = SHA256.HashData(RandomNumberGenerator.GetBytes(32));
        var second = SHA256.HashData(RandomNumberGenerator.GetBytes(32));
        var cancellationToken = CancellationToken.None;

        try
        {
            await using (var write = TestDatabase.CreateContext())
            {
                await new PostgresUserRepository(write).AddAsync(user);
                var sessions = new PostgresAuthenticatedSessionRepository(write);
                await sessions.AddAsync(new(first, user.Id, now, now.AddMinutes(20)), cancellationToken);
                await sessions.AddAsync(new(second, user.Id, now, now.AddMinutes(20)), cancellationToken);
            }

            await using var read = TestDatabase.CreateContext();
            var repository = new PostgresAuthenticatedSessionRepository(read);
            Assert.True(await repository.IsActiveAsync(first, user.Id, now, cancellationToken));
            Assert.False(await repository.IsActiveAsync(first, user.Id, now.AddMinutes(20), cancellationToken));
            Assert.False(await repository.IsActiveAsync(first, Guid.NewGuid(), now, cancellationToken));

            await using var concurrent = TestDatabase.CreateContext();
            await Task.WhenAll(
                repository.RevokeAsync(first, user.Id, now, cancellationToken),
                new PostgresAuthenticatedSessionRepository(concurrent)
                    .RevokeAsync(first, user.Id, now, cancellationToken));
            await repository.RevokeAsync(first, user.Id, now.AddSeconds(1), cancellationToken);

            Assert.False(await repository.IsActiveAsync(first, user.Id, now, cancellationToken));
            Assert.True(await repository.IsActiveAsync(second, user.Id, now, cancellationToken));
            Assert.Equal(now, (await read.AuthenticatedSessions.SingleAsync(session => session.IdHash == first)).RevokedAt);
        }
        finally
        {
            await using var cleanup = TestDatabase.CreateContext();
            await cleanup.Users.Where(candidate => candidate.Id == user.Id).ExecuteDeleteAsync();
        }
    }
}

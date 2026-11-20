using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.UnitTests.Api.Security;

internal sealed class InMemorySessionRepository : IAuthenticatedSessionRepository
{
    private readonly ConcurrentDictionary<string, (AuthenticatedSession Session, DateTime? RevokedAt)> _sessions = new();
    public IEnumerable<AuthenticatedSession> Sessions => _sessions.Values.Select(value => value.Session);
    public bool FailWrites { get; set; }
    public bool FailReads { get; set; }

    public Task AddAsync(AuthenticatedSession session, CancellationToken cancellationToken)
    {
        if (FailWrites || !_sessions.TryAdd(Convert.ToHexString(session.IdHash), (session, null)))
            throw new InvalidOperationException("Test session write failed.");
        return Task.CompletedTask;
    }

    public async Task<bool> IsActiveAsync(byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken) =>
        await GetActiveExpirationAsync(idHash, userId, now, cancellationToken) is not null;

    public Task<DateTime?> GetActiveExpirationAsync(byte[] idHash, Guid userId, DateTime now,
        CancellationToken cancellationToken)
    {
        if (FailReads)
            throw new InvalidOperationException("Test session read failed.");
        return Task.FromResult<DateTime?>(_sessions.TryGetValue(Convert.ToHexString(idHash), out var record) &&
            record.Session.UserId == userId && record.RevokedAt is null && record.Session.ExpiresAt > now
                ? record.Session.ExpiresAt : null);
    }

    public Task RevokeAsync(byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken)
    {
        if (FailWrites)
            throw new InvalidOperationException("Test session write failed.");
        var key = Convert.ToHexString(idHash);
        if (_sessions.TryGetValue(key, out var record) && record.Session.UserId == userId && record.RevokedAt is null)
            _sessions.TryUpdate(key, (record.Session, now), record);
        return Task.CompletedTask;
    }

    public static InMemorySessionRepository Register(IServiceCollection services)
    {
        var repository = new InMemorySessionRepository();
        services.AddSingleton<IAuthenticatedSessionRepository>(repository);
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthenticatedSessionService>();
        return repository;
    }

    public static async Task<AuthenticationProperties> IssueAsync(IServiceProvider services, Guid userId)
    {
        var session = await services.GetRequiredService<AuthenticatedSessionService>()
            .CreateAsync(userId, CancellationToken.None);
        var properties = new AuthenticationProperties
        {
            IssuedUtc = session.CreatedAt,
            ExpiresUtc = session.ExpiresAt
        };
        properties.SetString(SafeNetCookieAuthentication.SessionIdKey, session.Id);
        return properties;
    }
}

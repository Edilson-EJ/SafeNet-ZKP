using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.Interfaces.Repositories;

public interface IAuthenticatedSessionRepository
{
    Task AddAsync(AuthenticatedSession session, CancellationToken cancellationToken);
    Task<bool> IsActiveAsync(byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken);
    Task RevokeAsync(byte[] idHash, Guid userId, DateTime now, CancellationToken cancellationToken);
}

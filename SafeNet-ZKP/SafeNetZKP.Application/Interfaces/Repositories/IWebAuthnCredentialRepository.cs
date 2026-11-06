
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.Interfaces.Repositories;

public interface IWebAuthnCredentialRepository
{
    Task AddAsync(
        WebAuthnCredential credential,
        CancellationToken cancellationToken = default);

    Task<WebAuthnCredential?> GetByCredentialIdAsync(
        byte[] credentialId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);
}

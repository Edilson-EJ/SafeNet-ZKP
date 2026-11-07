
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.Infrastructure.Repositories;

public sealed class PostgresWebAuthnCredentialRepository
    : IWebAuthnCredentialRepository
{
    private readonly SafeNetZkpDbContext _context;

    public PostgresWebAuthnCredentialRepository(
        SafeNetZkpDbContext context)
    {
        _context = context;
    }

    public async Task AddAsync(
        WebAuthnCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _context.WebAuthnCredentials.AddAsync(
            credential,
            cancellationToken);

        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task<WebAuthnCredential?> GetByCredentialIdAsync(
        byte[] credentialId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        if (credentialId.Length == 0)
            return null;

        return await _context.WebAuthnCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(
                c => c.CredentialId.SequenceEqual(credentialId),
                cancellationToken);
    }

    public async Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
            return [];

        return await _context.WebAuthnCredentials
            .AsNoTracking()
            .Where(c => c.UserId == userId)
            .OrderBy(c => c.CreatedAt)
            .ToListAsync(cancellationToken);
    }
}

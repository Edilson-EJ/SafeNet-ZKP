using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.Interfaces.Repositories;

public interface INetworkAccessRepository
{
    Task<bool> AddAssociationAsync(NetworkAccessAssociation association, CancellationToken ct);
    Task<(NetworkAccessEntry? Entry, bool Created)> ReserveAsync(Guid associationId, Guid userId, byte[] sessionHash,
        Guid idempotencyKey, DateTimeOffset now, DateTimeOffset validUntil, DateTimeOffset accessUntil, CancellationToken ct);
    Task<NetworkAccessEntry?> FindOwnedAsync(Guid operationId, Guid userId, byte[] sessionHash, CancellationToken ct);
    Task<IReadOnlyList<NetworkAccessEntry>> ListOwnedAsync(Guid userId, byte[] sessionHash, int limit, CancellationToken ct);
    Task RecordAuthorizationAsync(Guid id, NetworkAccessState state, DateTimeOffset? confirmedUntil,
        DateTimeOffset now, CancellationToken ct);
    Task<bool> QueueRevocationAsync(Guid id, Guid userId, byte[] sessionHash, DateTimeOffset now, CancellationToken ct);
    Task<IReadOnlyList<NetworkAccessEntry>> ListPendingRevocationsAsync(int limit, CancellationToken ct);
    Task RecordRevocationAsync(Guid id, Guid revocationId, NetworkAccessState state, DateTimeOffset now, CancellationToken ct);
}

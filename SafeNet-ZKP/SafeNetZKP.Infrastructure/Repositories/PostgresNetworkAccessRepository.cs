using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.Infrastructure.Repositories;

public sealed class PostgresNetworkAccessRepository(SafeNetZkpDbContext db) : INetworkAccessRepository
{
    public async Task<bool> AddAssociationAsync(NetworkAccessAssociation association, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        if (association.ExpiresAt <= association.CreatedAt ||
            !await LockActiveSessionAsync(association.SessionHash, association.UserId, association.CreatedAt,
                association.ExpiresAt, ct))
            return false;

        var inserted = await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "NetworkAccessAssociations"
                ("Id", "GatewayId", "ConnectionId", "Generation", "UserId", "SessionHash",
                 "CreatedAt", "ExpiresAt", "LastRevision")
            VALUES ({association.Id}, {association.GatewayId}, {association.ConnectionId}, {association.Generation},
                    {association.UserId}, {association.SessionHash}, {association.CreatedAt}, {association.ExpiresAt}, 0)
            ON CONFLICT ("GatewayId", "ConnectionId", "Generation") DO NOTHING
            """, ct);
        await transaction.CommitAsync(ct);
        return inserted == 1;
    }

    public async Task<(NetworkAccessEntry? Entry, bool Created)> ReserveAsync(Guid associationId, Guid userId,
        byte[] sessionHash, Guid idempotencyKey, DateTimeOffset now, DateTimeOffset validUntil,
        DateTimeOffset accessUntil, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        if (!await LockActiveSessionAsync(sessionHash, userId, now, now, ct))
            return (null, false);

        var associations = await db.NetworkAccessAssociations.FromSqlInterpolated($"""
            SELECT * FROM "NetworkAccessAssociations"
            WHERE "Id" = {associationId} AND "UserId" = {userId} AND "SessionHash" = {sessionHash}
              AND "ExpiresAt" > {now}
            FOR UPDATE
            """).AsNoTracking().ToListAsync(ct);
        var association = associations.SingleOrDefault();
        if (association is null)
            return (null, false);

        var entries = db.NetworkAccessOperations.Where(item => item.AssociationId == associationId);
        var existing = await entries.AsNoTracking().Include(item => item.Association)
            .SingleOrDefaultAsync(item => item.IdempotencyKey == idempotencyKey, ct);
        if (existing is not null)
            return (existing, false);

        // PostgreSQL guarda microssegundos. O primeiro envio e as repetições devem usar os mesmos prazos.
        validUntil = AtPostgresPrecision(validUntil);
        accessUntil = AtPostgresPrecision(accessUntil);
        if (validUntil <= now || validUntil > accessUntil || accessUntil > association.ExpiresAt ||
            await entries.AnyAsync(item => item.AccessUntil > now &&
                item.State != NetworkAccessState.Denied && item.State != NetworkAccessState.Expired &&
                item.State != NetworkAccessState.Revoked &&
                item.RevocationState != NetworkAccessState.Revoked &&
                item.RevocationState != NetworkAccessState.Expired, ct))
            return (null, false);

        var revision = checked(association.LastRevision + 1);
        var entry = new NetworkAccessEntry
        {
            Id = Guid.NewGuid(), AssociationId = association.Id, IdempotencyKey = idempotencyKey,
            GrantId = Guid.NewGuid(), Revision = revision, CreatedAt = now, UpdatedAt = now,
            ValidUntil = validUntil, AccessUntil = accessUntil, State = NetworkAccessState.Pending
        };
        // Reserva a revisão seguinte para revogar esta concessão, inclusive antes da confirmação.
        await db.NetworkAccessAssociations.Where(item => item.Id == association.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.LastRevision, revision + 1), ct);
        db.NetworkAccessOperations.Add(entry);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        db.Entry(entry).State = EntityState.Detached;
        return (entry, true);
    }

    public Task<NetworkAccessEntry?> FindOwnedAsync(Guid operationId, Guid userId, byte[] sessionHash,
        CancellationToken ct) =>
        OwnedEntries(userId, sessionHash).AsNoTracking().Include(item => item.Association)
            .SingleOrDefaultAsync(item => item.Id == operationId, ct);

    public async Task<IReadOnlyList<NetworkAccessEntry>> ListOwnedAsync(Guid userId, byte[] sessionHash,
        int limit, CancellationToken ct) =>
        await OwnedEntries(userId, sessionHash).AsNoTracking().OrderByDescending(item => item.CreatedAt)
            .ThenBy(item => item.Id).Take(limit).ToListAsync(ct);

    public async Task RecordAuthorizationAsync(Guid id, NetworkAccessState state, DateTimeOffset? confirmedUntil,
        DateTimeOffset now, CancellationToken ct)
    {
        var entries = db.NetworkAccessOperations.Where(item => item.Id == id && item.RevocationId == null &&
            item.State != NetworkAccessState.Expired && item.State != NetworkAccessState.Revoked &&
            item.State != NetworkAccessState.Denied);
        if (state == NetworkAccessState.Authorized)
            entries = entries.Where(item => item.AccessUntil > now && confirmedUntil > now &&
                confirmedUntil <= item.AccessUntil);

        await entries.ExecuteUpdateAsync(update => update
            .SetProperty(item => item.State, item => state == NetworkAccessState.Denied &&
                item.GrantState == NetworkAccessState.Authorized ? NetworkAccessState.Indeterminate : state)
            .SetProperty(item => item.GrantState, item =>
                state == NetworkAccessState.Authorized || state == NetworkAccessState.Revoked ||
                state == NetworkAccessState.Expired ? state : item.GrantState)
            .SetProperty(item => item.ConfirmedUntil, item =>
                state == NetworkAccessState.Authorized ? confirmedUntil : item.ConfirmedUntil)
            .SetProperty(item => item.UpdatedAt, item => item.UpdatedAt > now ? item.UpdatedAt : now), ct);
    }

    public async Task<bool> QueueRevocationAsync(Guid id, Guid userId, byte[] sessionHash, DateTimeOffset now,
        CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        if (!await LockActiveSessionAsync(sessionHash, userId, now, now, ct))
            return false;

        var entries = OwnedEntries(userId, sessionHash).Where(item => item.Id == id);
        if (!await entries.AnyAsync(ct))
            return false;

        await QueueAsync(entries, now, ct);
        await transaction.CommitAsync(ct);
        return true;
    }

    // Deve participar da mesma transação da revogação da sessão web.
    internal Task QueueSessionRevocationsAsync(Guid userId, byte[] sessionHash, DateTimeOffset now,
        CancellationToken ct) => QueueAsync(OwnedEntries(userId, sessionHash), now, ct);

    private static Task<int> QueueAsync(IQueryable<NetworkAccessEntry> entries, DateTimeOffset now, CancellationToken ct) =>
        entries.Where(item => item.RevocationId == null && item.AccessUntil > now &&
                item.State != NetworkAccessState.Denied && item.State != NetworkAccessState.Expired &&
                item.State != NetworkAccessState.Revoked)
            .ExecuteUpdateAsync(update => update
                .SetProperty(item => item.RevocationId, item => (Guid?)Guid.NewGuid())
                .SetProperty(item => item.RevocationState, NetworkAccessState.Pending)
                .SetProperty(item => item.RevocationQueuedAt, now)
                .SetProperty(item => item.UpdatedAt, item => item.UpdatedAt > now ? item.UpdatedAt : now), ct);

    public async Task<IReadOnlyList<NetworkAccessEntry>> ListPendingRevocationsAsync(int limit, CancellationToken ct) =>
        await db.NetworkAccessOperations.AsNoTracking().Include(item => item.Association)
            .Where(item => item.RevocationState == NetworkAccessState.Pending ||
                item.RevocationState == NetworkAccessState.Indeterminate)
            .OrderBy(item => item.UpdatedAt).ThenBy(item => item.Id).Take(limit).ToListAsync(ct);

    public async Task RecordRevocationAsync(Guid id, Guid revocationId, NetworkAccessState state,
        DateTimeOffset now, CancellationToken ct)
    {
        await db.NetworkAccessOperations.Where(item => item.Id == id && item.RevocationId == revocationId &&
                (item.RevocationState == NetworkAccessState.Pending ||
                 item.RevocationState == NetworkAccessState.Indeterminate))
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.RevocationState, state)
                .SetProperty(item => item.GrantState, item =>
                    state == NetworkAccessState.Revoked || state == NetworkAccessState.Expired ? state : item.GrantState)
                .SetProperty(item => item.UpdatedAt, item => item.UpdatedAt > now ? item.UpdatedAt : now), ct);
    }

    private IQueryable<NetworkAccessEntry> OwnedEntries(Guid userId, byte[] sessionHash) =>
        db.NetworkAccessOperations.Where(item => item.Association.UserId == userId &&
            item.Association.SessionHash == sessionHash);

    private static DateTimeOffset AtPostgresPrecision(DateTimeOffset value) =>
        value.AddTicks(-(value.Ticks % TimeSpan.TicksPerMicrosecond));

    private async Task<bool> LockActiveSessionAsync(byte[] hash, Guid userId, DateTimeOffset now,
        DateTimeOffset requiredUntil, CancellationToken ct)
    {
        var matches = await db.AuthenticatedSessions.FromSqlInterpolated($"""
            SELECT * FROM "AuthenticatedSessions"
            WHERE "IdHash" = {hash} AND "UserId" = {userId} AND "RevokedAt" IS NULL
              AND "ExpiresAt" > {now} AND "ExpiresAt" >= {requiredUntil}
            FOR UPDATE
            """).AsNoTracking().ToListAsync(ct);
        return matches.Count == 1;
    }
}

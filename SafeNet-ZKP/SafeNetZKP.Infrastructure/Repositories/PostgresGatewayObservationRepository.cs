using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.Infrastructure.Repositories;

public sealed class PostgresGatewayObservationRepository(SafeNetZkpDbContext db) : IGatewayObservationRepository
{
    public async Task<bool> TryRecordAsync(GatewayObservation observation, CancellationToken ct) =>
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO "GatewayObservations"
                ("GatewayId", "Nonce", "ConnectionId", "Generation", "ObservedAt", "ExpiresAt")
            VALUES ({observation.GatewayId}, {observation.Nonce}, {observation.ConnectionId},
                    {observation.Generation}, {observation.ObservedAt}, {observation.ExpiresAt})
            ON CONFLICT ("GatewayId", "Nonce") DO NOTHING
            """, ct) == 1;
}

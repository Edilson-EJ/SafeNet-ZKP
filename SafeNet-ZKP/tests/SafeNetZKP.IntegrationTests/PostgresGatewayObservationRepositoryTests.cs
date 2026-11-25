using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Domain.CaptivePortal;
using SafeNetZKP.Infrastructure.Repositories;

namespace SafeNetZKP.IntegrationTests;

public sealed class PostgresGatewayObservationRepositoryTests
{
    [Fact]
    public async Task ConcurrentWritersPersistOnlyOneObservationPerGatewayNonce()
    {
        var gatewayId = Guid.NewGuid();
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var observedAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var observation = new GatewayObservation(gatewayId, nonce, Guid.NewGuid(), 1, observedAt, observedAt.AddMinutes(2));
        await using var first = TestDatabase.CreateContext();
        await using var second = TestDatabase.CreateContext();
        await using var read = TestDatabase.CreateContext();
        try
        {
            var results = await Task.WhenAll(
                new PostgresGatewayObservationRepository(first).TryRecordAsync(observation, CancellationToken.None),
                new PostgresGatewayObservationRepository(second).TryRecordAsync(
                    observation with { ConnectionId = Guid.NewGuid() }, CancellationToken.None));

            Assert.Single(results, accepted => accepted);
            var stored = await read.GatewayObservations.AsNoTracking()
                .SingleAsync(row => row.GatewayId == gatewayId && row.Nonce == nonce);
            if (results[0])
                Assert.Equal(observation, stored);
            else
                Assert.NotEqual(observation.ConnectionId, stored.ConnectionId);
            Assert.False(await new PostgresGatewayObservationRepository(read)
                .TryRecordAsync(observation, CancellationToken.None));
        }
        finally
        {
            await read.GatewayObservations.Where(row => row.GatewayId == gatewayId).ExecuteDeleteAsync();
        }
    }
}

using Microsoft.EntityFrameworkCore;
using Npgsql;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.IntegrationTests;

public static class TestDatabase
{
    public static SafeNetZkpDbContext CreateContext()
    {
        var connectionString = Environment.GetEnvironmentVariable(
            "SAFENET_TEST_CONNECTION_STRING");

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "A variável SAFENET_TEST_CONNECTION_STRING não foi configurada.");
        }

        var connection = new NpgsqlConnectionStringBuilder(connectionString);

        if (connection.Database != "safenet_zkp_test" ||
            connection.Port != 5433 ||
            (connection.Host != "127.0.0.1" &&
             !string.Equals(connection.Host, "localhost", StringComparison.OrdinalIgnoreCase) &&
             connection.Host != "::1"))
        {
            throw new InvalidOperationException(
                "Os testes exigem safenet_zkp_test em loopback, na porta 5433.");
        }

        var options = new DbContextOptionsBuilder<SafeNetZkpDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new SafeNetZkpDbContext(options);
    }
}

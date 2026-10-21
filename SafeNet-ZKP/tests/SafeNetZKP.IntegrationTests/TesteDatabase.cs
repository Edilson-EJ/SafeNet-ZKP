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

        if (connection.Database != "safenet_zkp_test")
        {
            throw new InvalidOperationException(
                "Os testes devem utilizar o banco safenet_zkp_test.");
        }

        var options = new DbContextOptionsBuilder<SafeNetZkpDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new SafeNetZkpDbContext(options);
    }
}
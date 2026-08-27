using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.IntegrationTests;

public static class TestDatabase
{
    private const string ConnectionString =
        "Host=localhost;Port=5432;Database=safenet_zkp_test;Username=safenet;Password=safenet_dev_password";

    public static SafeNetZkpDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<SafeNetZkpDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;

        return new SafeNetZkpDbContext(options);
    }
}
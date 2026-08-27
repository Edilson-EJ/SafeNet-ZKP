using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Repositories;

namespace SafeNetZKP.IntegrationTests;

public class PostgresUserRepositoryTests
{
    [Fact]
    public async Task AddAsync_ShouldPersistUserInPostgres()
    {
        // Arrange
        await using var context = TestDatabase.CreateContext();

        var repository = new PostgresUserRepository(context);

        var user = new User("Teste Integração");

        // Act
        await repository.AddAsync(user);

        // Assert
        var savedUser = await repository.GetByIdAsync(user.Id);

        Assert.NotNull(savedUser);
        Assert.Equal(user.Id, savedUser.Id);
        Assert.Equal("Teste Integração", savedUser.Name);
    }
}
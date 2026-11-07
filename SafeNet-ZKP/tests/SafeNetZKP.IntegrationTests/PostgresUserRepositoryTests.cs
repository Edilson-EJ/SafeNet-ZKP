
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Repositories;

namespace SafeNetZKP.IntegrationTests;

public class PostgresUserRepositoryTests
{
    [Fact]
    public async Task AddAsync_ShouldPersistUserInPostgres()
    {
        // Arrange
        var user = new User("Teste Integração");

        // Act - Salvar no PostgreSQL
        await using (var writeContext = TestDatabase.CreateContext())
        {
            var repository = new PostgresUserRepository(writeContext);

            await repository.AddAsync(user);
        }

        // Assert - Consultar utilizando um novo DbContext
        await using (var readContext = TestDatabase.CreateContext())
        {
            var repository = new PostgresUserRepository(readContext);

            var savedUser = await repository.GetByIdAsync(user.Id);

            Assert.NotNull(savedUser);
            Assert.Equal(user.Id, savedUser.Id);
            Assert.Equal("Teste Integração", savedUser.Name);
        }
    }
}

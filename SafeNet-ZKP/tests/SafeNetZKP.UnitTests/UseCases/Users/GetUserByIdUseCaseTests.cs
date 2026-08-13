using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.UnitTests.UseCases.Users;

public class GetUserByIdUseCaseTests
{
    [Fact]
    public async Task ExecuteAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var repository = new FakeUserRepository();

        var user = new User("Edilson");

        await repository.AddAsync(user);

        var useCase = new GetUserByIdUseCase(repository);

        // Act
        var response = await useCase.ExecuteAsync(user.Id);

        // Assert
        Assert.NotNull(response);
        Assert.Equal(user.Id, response.Id);
        Assert.Equal("Edilson", response.Name);
        Assert.Equal(user.CreatedAt, response.CreatedAt);
    }

    [Fact]
    public async Task ExecuteAsync_ShouldReturnNull_WhenUserDoesNotExist()
    {
        // Arrange
        var repository = new FakeUserRepository();

        var useCase = new GetUserByIdUseCase(repository);

        var id = Guid.NewGuid();

        // Act
        var response = await useCase.ExecuteAsync(id);

        // Assert
        Assert.Null(response);
    }

    private class FakeUserRepository : IUserRepository
    {
        private readonly List<User> _users = [];

        public Task AddAsync(User user)
        {
            _users.Add(user);

            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            var user = _users.FirstOrDefault(x => x.Id == id);

            return Task.FromResult(user);
        }
    }
}
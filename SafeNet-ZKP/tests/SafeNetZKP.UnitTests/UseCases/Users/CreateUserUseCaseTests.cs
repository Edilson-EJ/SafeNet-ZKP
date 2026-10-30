using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.UnitTests.UseCases.Users;

public class CreateUserUseCaseTests
{
    [Fact]
    public async Task ExecuteAsync_ShouldCreateUser()
    {
        // Arrange
        var repository = new FakeUserRepository();

        var useCase = new CreateUserUseCase(repository);

        var request = new CreateUserRequest("Edilson");

        // Act
        var response = await useCase.ExecuteAsync(request);

        // Assert - resposta
        Assert.NotEqual(Guid.Empty, response.Id);
        Assert.Equal("Edilson", response.Name);
        Assert.NotEqual(default, response.CreatedAt);

        // Assert - persistência no repositório falso
        var savedUser = Assert.Single(repository.Users);

        Assert.Equal(response.Id, savedUser.Id);
        Assert.Equal(response.Name, savedUser.Name);
        Assert.Equal(response.CreatedAt, savedUser.CreatedAt);
    }

    [Fact]
    public void User_ShouldNotBeCreated_WhenNameIsEmpty()
    {
        // Act
        var action = () => new User("");

        // Assert
        var exception = Assert.Throws<ArgumentException>(action);

        Assert.Equal(
            "O nome do usuário é obrigatório. (Parameter 'name')",
            exception.Message);
    }

    private class FakeUserRepository : IUserRepository
    {
        public List<User> Users { get; } = [];

        public Task AddAsync(User user)
        {
            Users.Add(user);

            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            var user = Users.FirstOrDefault(x => x.Id == id);

            return Task.FromResult(user);
        }


    }
}
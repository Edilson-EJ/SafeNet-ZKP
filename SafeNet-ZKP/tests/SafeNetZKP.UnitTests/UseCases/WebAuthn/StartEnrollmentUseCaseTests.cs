
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;
using SafeNetZKP.Domain.Entities;
using Xunit;

namespace SafeNetZKP.UnitTests.UseCases.WebAuthn;

public class StartEnrollmentUseCaseTests
{
    [Fact]
    public async Task ExecuteAsync_ShouldCreateUserAndIssueEnrollmentToken()
    {
        // Arrange
        var repository = new FakeUserRepository();
        var ticketIssuer = new FakeEnrollmentTicketIssuer();

        var useCase = new StartEnrollmentUseCase(
            repository,
            ticketIssuer);

        // Act
        var result = await useCase.ExecuteAsync("Usuário Teste");

        // Assert
        Assert.NotEqual(Guid.Empty, result.UserId);
        Assert.Equal("Usuário Teste", result.Name);
        Assert.Equal("token-de-teste", result.EnrollmentToken);

        // Verifica se o usuário foi persistido.
        Assert.NotNull(repository.SavedUser);
        Assert.Equal(repository.SavedUser.Id, result.UserId);
        Assert.Equal(repository.SavedUser.CreatedAt, result.CreatedAt);

        // O token pertence ao usuário recém-criado.
        Assert.Equal(result.UserId, ticketIssuer.LastUserId);
        Assert.Equal(1, ticketIssuer.IssueCount);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRepositoryFails_ShouldNotIssueToken()
    {
        // Arrange
        var repository = new FakeUserRepository
        {
            ShouldFail = true
        };

        var ticketIssuer = new FakeEnrollmentTicketIssuer();

        var useCase = new StartEnrollmentUseCase(
            repository,
            ticketIssuer);

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => useCase.ExecuteAsync("Usuário Teste"));

        // Assert
        Assert.Null(repository.SavedUser);
        Assert.Equal(0, ticketIssuer.IssueCount);
        Assert.Null(ticketIssuer.LastUserId);
    }

    [Fact]
    public async Task ExecuteAsync_WithEmptyName_ShouldNotCreateUserOrToken()
    {
        // Arrange
        var repository = new FakeUserRepository();
        var ticketIssuer = new FakeEnrollmentTicketIssuer();

        var useCase = new StartEnrollmentUseCase(
            repository,
            ticketIssuer);

        // Act
        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => useCase.ExecuteAsync(""));

        // Assert
        Assert.Null(repository.SavedUser);
        Assert.Equal(0, ticketIssuer.IssueCount);
    }

    private sealed class FakeUserRepository : IUserRepository
    {
        public User? SavedUser { get; private set; }

        public bool ShouldFail { get; set; }

        public Task AddAsync(User user)
        {
            if (ShouldFail)
            {
                throw new InvalidOperationException(
                    "Falha simulada na persistência.");
            }

            SavedUser = user;

            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            var user = SavedUser?.Id == id
                ? SavedUser
                : null;

            return Task.FromResult(user);
        }
    }

    private sealed class FakeEnrollmentTicketIssuer
        : IEnrollmentTicketIssuer
    {
        public Guid? LastUserId { get; private set; }

        public int IssueCount { get; private set; }

        public string Issue(Guid userId)
        {
            LastUserId = userId;
            IssueCount++;

            return "token-de-teste";
        }
    }
}

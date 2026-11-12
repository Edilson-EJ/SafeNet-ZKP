
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.Security.Cryptography;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Repositories;



namespace SafeNetZKP.IntegrationTests;

public class PostgresWebAuthnCredentialRepositoryTests
{
    [Fact]
    public async Task AddAsync_ShouldPersistCredentialInPostgres()
    {
        // Arrange
        var user = new User("Teste WebAuthn");

        var credentialId = RandomNumberGenerator.GetBytes(32);
        byte[] publicKeyCose = [1, 2, 3];

        var credential = new WebAuthnCredential(
            user.Id,
            credentialId,
            publicKeyCose,
            0);

        try
        {
            // Act - Salvar usuário e credencial
            await using (var writeContext = TestDatabase.CreateContext())
            {
                var userRepository =
                    new PostgresUserRepository(writeContext);

                var credentialRepository =
                    new PostgresWebAuthnCredentialRepository(writeContext);

                await userRepository.AddAsync(user);
                await credentialRepository.AddAsync(credential);
            }

            // Assert - Recuperar usando outro DbContext
            await using (var readContext = TestDatabase.CreateContext())
            {
                var repository =
                    new PostgresWebAuthnCredentialRepository(readContext);

                var savedCredential =
                    await repository.GetByCredentialIdAsync(credentialId);

                Assert.NotNull(savedCredential);

                Assert.Equal(credential.Id, savedCredential.Id);
                Assert.Equal(user.Id, savedCredential.UserId);
                Assert.Equal(credentialId, savedCredential.CredentialId);
                Assert.Equal(publicKeyCose, savedCredential.PublicKeyCose);

                var userCredentials =
                    await repository.GetByUserIdAsync(user.Id);

                Assert.Contains(
                    userCredentials,
                    c => c.Id == credential.Id);
            }
        }
        finally
        {
            // Remove somente o usuário criado neste teste.
            // A credencial será removida pelo ON DELETE CASCADE.
            await using var cleanupContext = TestDatabase.CreateContext();

            await cleanupContext.Users
                .Where(u => u.Id == user.Id)
                .ExecuteDeleteAsync();
        }
    }

    
    
    [Fact]
    public async Task GetByCredentialIdAsync_WhenCredentialDoesNotExist_ShouldReturnNull()
    {
        // Arrange
        await using var context = TestDatabase.CreateContext();

        var repository =
            new PostgresWebAuthnCredentialRepository(context);

        var credentialId = RandomNumberGenerator.GetBytes(32);

        // Act
        var result = await repository.GetByCredentialIdAsync(credentialId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByUserIdAsync_WhenUserHasNoCredentials_ShouldReturnEmptyList()
    {
        // Arrange
        await using var context = TestDatabase.CreateContext();

        var repository =
            new PostgresWebAuthnCredentialRepository(context);

        var userId = Guid.NewGuid();

        // Act
        var result = await repository.GetByUserIdAsync(userId);

        // Assert
        Assert.Empty(result);
    }


    [Fact]
    public async Task AddAsync_WithDuplicateCredentialId_ShouldThrowException()
    {
        // Arrange
        var user = new User("Teste Credencial Duplicada");

        var credentialId = RandomNumberGenerator.GetBytes(32);

        var firstCredential = new WebAuthnCredential(
            user.Id,
            credentialId,
            [1, 2, 3],
            0);

        var duplicateCredential = new WebAuthnCredential(
            user.Id,
            credentialId,
            [4, 5, 6],
            0);

        try
        {
            await using var context = TestDatabase.CreateContext();

            var userRepository = new PostgresUserRepository(context);

            var credentialRepository =
                new PostgresWebAuthnCredentialRepository(context);

            await userRepository.AddAsync(user);

            // Salvar a primeira credencial.
            await credentialRepository.AddAsync(firstCredential);

            // Act - Tentar salvar outra credencial com o mesmo ID.
            var exception = await Assert.ThrowsAsync<DbUpdateException>(
                () => credentialRepository.AddAsync(duplicateCredential));

            // Assert - Verificar a violação de unicidade.
            var postgresException =
                Assert.IsType<PostgresException>(exception.InnerException);

            Assert.Equal(
                PostgresErrorCodes.UniqueViolation,
                postgresException.SqlState);

            Assert.Equal(
                "IX_WebAuthnCredentials_CredentialId",
                postgresException.ConstraintName);
        }
        finally
        {
            // Limpar os dados criados pelo teste.
            await using var cleanupContext = TestDatabase.CreateContext();

            await cleanupContext.Users
                .Where(u => u.Id == user.Id)
                .ExecuteDeleteAsync();
        }
    }



}

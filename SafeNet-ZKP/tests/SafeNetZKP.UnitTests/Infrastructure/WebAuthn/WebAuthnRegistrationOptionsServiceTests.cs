
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnRegistrationOptionsServiceTests
{
    [Fact]
    public async Task GenerateAsync_ShouldGenerateAndStoreRegistrationOptions()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var repository = new FakeCredentialRepository();
        var store = new WebAuthnRegistrationStore(cache);
        var service = CreateService(repository, store);

        var user = new User("Usuário Teste");

        // Act
        var (operationId, options) =
            await service.GenerateAsync(user);

        var storedOptions = store.Take(operationId, user.Id);

        // Assert
        Assert.NotEqual(Guid.Empty, operationId);
        Assert.Equal("localhost", options.Rp.Id);
        Assert.Equal(user.Id.ToByteArray(), options.User.Id);
        Assert.Equal(user.Name, options.User.Name);

        Assert.True(options.Challenge.Length >= 16);

        Assert.NotNull(storedOptions);
        Assert.Equal(
            options.Challenge,
            storedOptions.Challenge);
    }

    [Fact]
    public async Task GenerateAsync_ShouldExcludeExistingCredentials()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var user = new User("Usuário Teste");
        var repository = new FakeCredentialRepository();

        byte[] existingCredentialId = [1, 2, 3, 4];

        await repository.AddAsync(
            new WebAuthnCredential(
                user.Id,
                existingCredentialId,
                [5, 6, 7],
                0));

        var store = new WebAuthnRegistrationStore(cache);
        var service = CreateService(repository, store);

        // Act
        var (_, options) = await service.GenerateAsync(user);

        // Assert
        var excludedCredential =
            Assert.Single(options.ExcludeCredentials);

        Assert.Equal(
            existingCredentialId,
            excludedCredential.Id);
    }

    private static WebAuthnRegistrationOptionsService CreateService(
        IWebAuthnCredentialRepository repository,
        WebAuthnRegistrationStore store)
    {
        IFido2 fido2 = new Fido2NetLib.Fido2(
            new Fido2Configuration
            {
                RPID = "localhost",
                RPName = "SafeNet-ZKP",
                Origins = new HashSet<string>
                {
                    "http://localhost:4200"
                },
                ChallengeSize = 32
            });

        return new WebAuthnRegistrationOptionsService(
            fido2,
            repository,
            store);
    }

    private sealed class FakeCredentialRepository
        : IWebAuthnCredentialRepository
    {
        private readonly List<WebAuthnCredential> _credentials = [];

        public Task AddAsync(
            WebAuthnCredential credential,
            CancellationToken cancellationToken = default)
        {
            _credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task<WebAuthnCredential?> GetByCredentialIdAsync(
            byte[] credentialId,
            CancellationToken cancellationToken = default)
        {
            var credential = _credentials.FirstOrDefault(
                c => c.CredentialId.SequenceEqual(credentialId));

            return Task.FromResult(credential);
        }

        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<WebAuthnCredential> credentials =
                _credentials
                    .Where(c => c.UserId == userId)
                    .ToList();

            return Task.FromResult(credentials);
        }
    }
}

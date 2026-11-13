
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnRegistrationStoreTests
{
    [Fact]
    public void StoreAndTake_ShouldReturnOriginalOptions()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var userId = Guid.NewGuid();
        var options = CreateOptions();

        // Act
        var operationId = store.Store(userId, options);
        var result = store.Take(operationId, userId);

        // Assert
        Assert.NotEqual(Guid.Empty, operationId);
        Assert.NotNull(result);
        Assert.Equal(options.Challenge, result.Challenge);
    }

    [Fact]
    public void Take_WithDifferentUser_ShouldReturnNull()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var ownerId = Guid.NewGuid();
        var anotherUserId = Guid.NewGuid();

        var operationId = store.Store(ownerId, CreateOptions());

        // Act
        var result = store.Take(operationId, anotherUserId);

        // Assert
        Assert.Null(result);

        // O proprietário ainda pode recuperar a operação.
        Assert.NotNull(store.Take(operationId, ownerId));
    }

    [Fact]
    public void Take_WhenCalledTwice_ShouldReturnNull()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var userId = Guid.NewGuid();
        var operationId = store.Store(userId, CreateOptions());

        // Act
        var firstResult = store.Take(operationId, userId);
        var secondResult = store.Take(operationId, userId);

        // Assert
        Assert.NotNull(firstResult);
        Assert.Null(secondResult);
    }

    [Fact]
    public void Take_WhenRegistrationExpires_ShouldReturnNull()
    {
        // Arrange
        var clock = new TestClock();

        using var cache = new MemoryCache(new MemoryCacheOptions
        {
            Clock = clock
        });

        var store = new WebAuthnRegistrationStore(cache);
        var userId = Guid.NewGuid();

        var validOperationId = store.Store(
            userId,
            CreateOptions());

        var expiredOperationId = store.Store(
            userId,
            CreateOptions());

        // Act - Avançar 4 minutos e 59 segundos.
        clock.Advance(
            TimeSpan.FromMinutes(4) +
            TimeSpan.FromSeconds(59));

        var validResult = store.Take(validOperationId, userId);

        // Avançar mais 2 segundos: total de 5 minutos e 1 segundo.
        clock.Advance(TimeSpan.FromSeconds(2));

        var expiredResult = store.Take(expiredOperationId, userId);

        // Assert
        Assert.NotNull(validResult);
        Assert.Null(expiredResult);

        // A operação expirada continua indisponível.
        Assert.Null(store.Take(expiredOperationId, userId));
    }

    private static CredentialCreateOptions CreateOptions()
    {
        // Opções fictícias utilizadas apenas nos testes do cache.
        const string json = """
        {
          "rp": {
            "id": "localhost",
            "name": "SafeNet-ZKP"
          },
          "user": {
            "id": "dGVzdA",
            "name": "usuario-teste",
            "displayName": "Usuário Teste"
          },
          "challenge": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
          "pubKeyCredParams": [
            {
              "type": "public-key",
              "alg": -7
            }
          ],
          "timeout": 60000,
          "attestation": "none",
          "excludeCredentials": []
        }
        """;

        return CredentialCreateOptions.FromJson(json);
    }

    // Relógio simulado para testar a expiração sem esperar.
    private sealed class TestClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; private set; } =
            new DateTimeOffset(
                2026, 1, 1, 0, 0, 0,
                TimeSpan.Zero);

        public void Advance(TimeSpan duration)
        {
            UtcNow = UtcNow.Add(duration);
        }
    }
}

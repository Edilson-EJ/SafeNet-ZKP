
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnRegistrationStoreTests
{
    [Fact]
    public void StoreAndTake_ShouldReturnOriginalOptions()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var userId = Guid.NewGuid();
        var options = CreateOptions();

        var operationId = store.Store(userId, options);
        var result = store.Take(operationId, userId);

        Assert.NotEqual(Guid.Empty, operationId);
        Assert.NotNull(result);
        Assert.Equal(options.Challenge, result.Challenge);
    }

    [Fact]
    public void Take_WithDifferentUser_ShouldReturnNull()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var ownerId = Guid.NewGuid();
        var anotherUserId = Guid.NewGuid();
        var operationId = store.Store(ownerId, CreateOptions());

        var result = store.Take(operationId, anotherUserId);

        Assert.Null(result);
        Assert.NotNull(store.Take(operationId, ownerId));
    }

    [Fact]
    public void Take_WhenCalledTwice_ShouldReturnNull()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnRegistrationStore(cache);

        var userId = Guid.NewGuid();
        var operationId = store.Store(userId, CreateOptions());

        var firstResult = store.Take(operationId, userId);
        var secondResult = store.Take(operationId, userId);

        Assert.NotNull(firstResult);
        Assert.Null(secondResult);
    }

    private static CredentialCreateOptions CreateOptions()
    {
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
}

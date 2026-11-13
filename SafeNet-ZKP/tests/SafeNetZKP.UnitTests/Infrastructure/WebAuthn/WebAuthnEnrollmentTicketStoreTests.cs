
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnEnrollmentTicketStoreTests
{
    [Fact]
    public void Issue_ShouldGenerateUniqueTokensAndAssociateUser()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnEnrollmentTicketStore(cache);

        var userId = Guid.NewGuid();

        // Act
        var firstToken = store.Issue(userId);
        var secondToken = store.Issue(userId);

        // Assert
        Assert.Matches("^[A-F0-9]{64}$", firstToken);
        Assert.Matches("^[A-F0-9]{64}$", secondToken);

        Assert.NotEqual(firstToken, secondToken);

        Assert.Equal(userId, store.TryGetUserId(firstToken));
        Assert.Equal(userId, store.TryGetUserId(secondToken));
    }

    [Fact]
    public void Consume_WithDifferentUser_ShouldReturnFalse()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnEnrollmentTicketStore(cache);

        var ownerId = Guid.NewGuid();
        var anotherUserId = Guid.NewGuid();

        var token = store.Issue(ownerId);

        // Act
        var result = store.Consume(token, anotherUserId);

        // Assert
        Assert.False(result);

        // O token permanece associado ao proprietário.
        Assert.Equal(ownerId, store.TryGetUserId(token));
    }

    [Fact]
    public void Consume_WhenCalledTwice_ShouldReturnFalse()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnEnrollmentTicketStore(cache);

        var userId = Guid.NewGuid();
        var token = store.Issue(userId);

        // Act
        var firstResult = store.Consume(token, userId);
        var secondResult = store.Consume(token, userId);

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);

        // O token consumido não pode ser recuperado.
        Assert.Null(store.TryGetUserId(token));
    }

    [Fact]
    public void Token_WhenExpired_ShouldBeUnavailable()
    {
        // Arrange
        var clock = new TestClock();

        using var cache = new MemoryCache(new MemoryCacheOptions
        {
            Clock = clock
        });

        var store = new WebAuthnEnrollmentTicketStore(cache);

        var userId = Guid.NewGuid();
        var token = store.Issue(userId);

        // Act - Avançar 9 minutos e 59 segundos.
        clock.Advance(
            TimeSpan.FromMinutes(9) +
            TimeSpan.FromSeconds(59));

        var beforeExpiration = store.TryGetUserId(token);

        // Avançar mais 2 segundos.
        // Tempo total: 10 minutos e 1 segundo.
        clock.Advance(TimeSpan.FromSeconds(2));

        var afterExpiration = store.TryGetUserId(token);
        var consumeResult = store.Consume(token, userId);

        // Assert
        Assert.Equal(userId, beforeExpiration);
        Assert.Null(afterExpiration);
        Assert.False(consumeResult);
    }

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

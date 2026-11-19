using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnAuthenticationOptionsTests
{
    [Fact]
    public void Generate_BindsDistinctChallengesToOperations()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnAuthenticationStore(cache);
        var service = CreateService(store);
        var first = service.Generate();
        var second = service.Generate();

        Assert.Matches("^[A-F0-9]{64}$", first.OperationId);
        Assert.NotEqual(first.OperationId, second.OperationId);
        Assert.NotEqual(first.Options.Challenge, second.Options.Challenge);
        Assert.True(first.Options.Challenge.Length >= 32);
        Assert.Equal("localhost", first.Options.RpId);
        Assert.Empty(first.Options.AllowCredentials);
        Assert.Equal(UserVerificationRequirement.Required, first.Options.UserVerification);
        Assert.Equal(second.Options.Challenge, store.Take(second.OperationId)!.Challenge);
        Assert.Equal(first.Options.Challenge, store.Take(first.OperationId)!.Challenge);
    }

    [Fact]
    public void Take_RejectsUnknownOrMalformedIdWithoutConsumingOtherOperation()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnAuthenticationStore(cache);
        var operation = CreateService(store).Generate();
        Assert.Null(store.Take(null));
        Assert.Null(store.Take("invalid"));
        Assert.Null(store.Take(new string('z', 64)));
        Assert.Null(store.Take(new string('0', 64)));
        Assert.NotNull(store.Take(operation.OperationId));
        Assert.Null(store.Take(operation.OperationId));
    }

    [Fact]
    public void Take_ExpiresAfterFiveMinutes()
    {
        var clock = new TestClock();
        using var cache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var store = new WebAuthnAuthenticationStore(cache);
        var service = CreateService(store);
        var valid = service.Generate();
        var expired = service.Generate();
        clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));
        Assert.NotNull(store.Take(valid.OperationId));
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Null(store.Take(expired.OperationId));
    }

    [Fact]
    public async Task Take_ConcurrentCalls_OnlyOneSucceeds()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnAuthenticationStore(cache);
        var operation = CreateService(store).Generate();
        var calls = Enumerable.Range(0, 32).Select(_ => Task.Run(() => store.Take(operation.OperationId)));
        Assert.Single(await Task.WhenAll(calls), result => result is not null);
    }

    [Fact]
    public void Store_KeepsSnapshotIndependentOfCallerMutation()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var store = new WebAuthnAuthenticationStore(cache);
        var operation = CreateService(store).Generate();
        var challenge = (byte[])operation.Options.Challenge.Clone();
        operation.Options.Challenge[0] ^= 0xff;
        Assert.Equal(challenge, store.Take(operation.OperationId)!.Challenge);
    }

    private static WebAuthnAuthenticationOptionsService CreateService(WebAuthnAuthenticationStore store)
    {
        IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
        {
            RPID = "localhost", RPName = "SafeNet", ChallengeSize = 32,
            Origins = new HashSet<string> { "http://localhost:4200" }
        });
        return new WebAuthnAuthenticationOptionsService(fido, store);
    }

    private sealed class TestClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UtcNow;
        public void Advance(TimeSpan duration) => UtcNow = UtcNow.Add(duration);
    }
}

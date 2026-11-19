
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnEnrollmentOptionsServiceTests
{
    [Fact]
    public async Task GenerateAsync_WhenTokenIsReused_ShouldRejectSecondRequest()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var user = new User("Visitante Teste");
        var tickets = new WebAuthnEnrollmentTicketStore(cache);
        var service = CreateService(user, tickets, new WebAuthnRegistrationStore(cache));
        var token = tickets.Issue(user.Id);

        Assert.NotNull(await service.GenerateAsync(token));
        Assert.Null(await service.GenerateAsync(token));
    }

    [Fact]
    public async Task GenerateAsync_ConcurrentRequests_OnlyOneSucceeds()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var user = new User("Visitante Teste");
        var tickets = new WebAuthnEnrollmentTicketStore(cache);
        var service = CreateService(user, tickets, new WebAuthnRegistrationStore(cache));
        var token = tickets.Issue(user.Id);
        using var gate = new ManualResetEventSlim(false);

        var requests = Enumerable.Range(0, 20).Select(_ => Task.Run(async () =>
        {
            gate.Wait();
            return await service.GenerateAsync(token);
        })).ToArray();
        gate.Set();
        var results = await Task.WhenAll(requests);

        Assert.Single(results, result => result is not null);
    }

    [Fact]
    public async Task GenerateAsync_WithValidToken_ShouldGenerateOptions()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var user = new User("Visitante Teste");

        var ticketStore = new WebAuthnEnrollmentTicketStore(cache);
        var registrationStore = new WebAuthnRegistrationStore(cache);

        var enrollmentToken = ticketStore.Issue(user.Id);

        var service = CreateService(
            user,
            ticketStore,
            registrationStore);

        // Act
        var result = await service.GenerateAsync(enrollmentToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotEqual(Guid.Empty, result.OperationId);

        Assert.Equal("localhost", result.Options.Rp.Id);
        Assert.Equal(user.Id.ToByteArray(), result.Options.User.Id);
        Assert.True(result.Options.Challenge.Length >= 16);

        // Verifica se as opções foram armazenadas.
        var storedOptions = registrationStore.Take(
            result.OperationId,
            user.Id);

        Assert.NotNull(storedOptions);

        Assert.Equal(
            result.Options.Challenge,
            storedOptions.Challenge);
    }

    [Fact]
    public async Task GenerateAsync_WithInvalidToken_ShouldReturnNull()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var user = new User("Visitante Teste");

        var ticketStore = new WebAuthnEnrollmentTicketStore(cache);
        var registrationStore = new WebAuthnRegistrationStore(cache);

        var service = CreateService(
            user,
            ticketStore,
            registrationStore);

        // Act
        var result = await service.GenerateAsync("token-invalido");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GenerateAsync_WithExpiredToken_ShouldReturnNull()
    {
        // Arrange
        var clock = new TestClock();

        using var cache = new MemoryCache(new MemoryCacheOptions
        {
            Clock = clock
        });

        var user = new User("Visitante Teste");

        var ticketStore = new WebAuthnEnrollmentTicketStore(cache);
        var registrationStore = new WebAuthnRegistrationStore(cache);

        var enrollmentToken = ticketStore.Issue(user.Id);

        var service = CreateService(
            user,
            ticketStore,
            registrationStore);

        // Avança o relógio em 11 minutos.
        clock.Advance(TimeSpan.FromMinutes(11));

        // Act
        var result = await service.GenerateAsync(enrollmentToken);

        // Assert
        Assert.Null(result);
        Assert.Null(ticketStore.TryGetUserId(enrollmentToken));
    }

    [Fact]
    public async Task GenerateAsync_WhenUserDoesNotExist_ShouldReturnNull()
    {
        // Arrange
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var ticketStore = new WebAuthnEnrollmentTicketStore(cache);
        var registrationStore = new WebAuthnRegistrationStore(cache);

        // O token existe, mas o usuário não está no repositório.
        var nonexistentUserId = Guid.NewGuid();

        var enrollmentToken = ticketStore.Issue(nonexistentUserId);

        var service = CreateService(
            null,
            ticketStore,
            registrationStore);

        // Act
        var result = await service.GenerateAsync(enrollmentToken);

        // Assert
        Assert.Null(result);
        Assert.Null(ticketStore.TryGetUserId(enrollmentToken));
    }

    private static WebAuthnEnrollmentOptionsService CreateService(
        User? user,
        WebAuthnEnrollmentTicketStore ticketStore,
        WebAuthnRegistrationStore registrationStore)
    {
        var userRepository = new FakeUserRepository(user);
        var credentialRepository = new FakeCredentialRepository();

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

        var registrationOptionsService =
            new WebAuthnRegistrationOptionsService(
                fido2,
                credentialRepository,
                registrationStore);

        return new WebAuthnEnrollmentOptionsService(
            ticketStore,
            userRepository,
            registrationOptionsService);
    }

    private sealed class FakeUserRepository : IUserRepository
    {
        private User? _user;

        public FakeUserRepository(User? user)
        {
            _user = user;
        }

        public Task AddAsync(User user)
        {
            _user = user;
            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            var result = _user?.Id == id ? _user : null;

            return Task.FromResult(result);
        }
    }

    private sealed class FakeCredentialRepository
        : IWebAuthnCredentialRepository
    {
        public Task AddAsync(
            WebAuthnCredential credential,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<WebAuthnCredential?> GetByCredentialIdAsync(
            byte[] credentialId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<WebAuthnCredential?>(null);
        }

        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<WebAuthnCredential> credentials = [];

            return Task.FromResult(credentials);
        }
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

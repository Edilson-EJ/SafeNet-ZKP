using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Infrastructure.WebAuthn;

namespace SafeNetZKP.IntegrationTests;

public class WebAuthnRegistrationCompletionPostgresTests
{
    [Fact]
    public async Task Completion_PersistsVerifiedCredential_AndRejectsDuplicate()
    {
        var user = new User("Registro de integração");
        var credentialId = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        try
        {
            await using (var context = TestDatabase.CreateContext())
                await new PostgresUserRepository(context).AddAsync(user);

            using var cache = new MemoryCache(new MemoryCacheOptions());
            var store = new WebAuthnRegistrationStore(cache);
            IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
            {
                RPID = "localhost", RPName = "SafeNet",
                Origins = new HashSet<string> { "http://localhost:4200" }, ChallengeSize = 32
            });

            await using (var context = TestDatabase.CreateContext())
            {
                var repository = new PostgresWebAuthnCredentialRepository(context);
                var optionsService = new WebAuthnRegistrationOptionsService(fido, repository, store);
                var completion = new WebAuthnRegistrationCompletionService(fido, store, repository);
                var (operation, options) = await optionsService.GenerateAsync(user, completionToken: token);
                var response = MakeResponse(options, credentialId, out var expectedPublicKey);
                Assert.True(await completion.CompleteAsync(operation, token, response));
                Assert.False(await completion.CompleteAsync(operation, token, response));
                var saved = await repository.GetByCredentialIdAsync(credentialId);
                Assert.Equal(expectedPublicKey, saved!.PublicKeyCose);
            }

            await using (var context = TestDatabase.CreateContext())
            {
                var repository = new PostgresWebAuthnCredentialRepository(context);
                var stored = await repository.GetByCredentialIdAsync(credentialId);
                Assert.NotNull(stored);
                Assert.Equal(user.Id, stored.UserId);
                Assert.NotEmpty(stored.PublicKeyCose);
                Assert.Equal(0u, stored.SignatureCounter);

                var optionsService = new WebAuthnRegistrationOptionsService(fido, repository, store);
                var completion = new WebAuthnRegistrationCompletionService(fido, store, repository);
                var (operation, options) = await optionsService.GenerateAsync(user, completionToken: token);
                Assert.False(await completion.CompleteAsync(operation, token, MakeResponse(options, credentialId, out _)));
                Assert.Single(await repository.GetByUserIdAsync(user.Id));
            }
        }
        finally
        {
            await using var context = TestDatabase.CreateContext();
            await context.Users.Where(u => u.Id == user.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task ConcurrentRegistrations_SameCredential_OnlyOneIsPersisted()
    {
        var user = new User("Concorrência de integração");
        var credentialId = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        try
        {
            await using (var context = TestDatabase.CreateContext())
                await new PostgresUserRepository(context).AddAsync(user);

            using var cache = new MemoryCache(new MemoryCacheOptions());
            var store = new WebAuthnRegistrationStore(cache);
            IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
            {
                RPID = "localhost", RPName = "SafeNet",
                Origins = new HashSet<string> { "http://localhost:4200" }, ChallengeSize = 32
            });
            await using var firstContext = TestDatabase.CreateContext();
            await using var secondContext = TestDatabase.CreateContext();
            var firstRepository = new PostgresWebAuthnCredentialRepository(firstContext);
            var secondRepository = new PostgresWebAuthnCredentialRepository(secondContext);
            var firstOptions = await new WebAuthnRegistrationOptionsService(fido, firstRepository, store)
                .GenerateAsync(user, completionToken: token);
            var secondOptions = await new WebAuthnRegistrationOptionsService(fido, secondRepository, store)
                .GenerateAsync(user, completionToken: token);
            var barrier = new InsertBarrier();
            var first = new WebAuthnRegistrationCompletionService(fido, store, new BarrierRepository(firstRepository, barrier));
            var second = new WebAuthnRegistrationCompletionService(fido, store, new BarrierRepository(secondRepository, barrier));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var results = await Task.WhenAll(
                first.CompleteAsync(firstOptions.OperationId, token, MakeResponse(firstOptions.Options, credentialId, out _), timeout.Token),
                second.CompleteAsync(secondOptions.OperationId, token, MakeResponse(secondOptions.Options, credentialId, out _), timeout.Token));
            Assert.Single(results, result => result);
            await using var checkContext = TestDatabase.CreateContext();
            var saved = await new PostgresWebAuthnCredentialRepository(checkContext).GetByUserIdAsync(user.Id);
            Assert.Single(saved);
            Assert.Equal(credentialId, saved[0].CredentialId);
        }
        finally
        {
            await using var context = TestDatabase.CreateContext();
            await context.Users.Where(u => u.Id == user.Id).ExecuteDeleteAsync();
        }
    }

    private sealed class InsertBarrier
    {
        private int _arrivals;
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _arrivals) == 2) _ready.TrySetResult();
            await _ready.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class BarrierRepository(IWebAuthnCredentialRepository inner, InsertBarrier barrier)
        : IWebAuthnCredentialRepository
    {
        public async Task AddAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default)
        {
            await barrier.WaitAsync(cancellationToken);
            await inner.AddAsync(credential, cancellationToken);
        }
        public Task<WebAuthnCredential?> GetByCredentialIdAsync(byte[] id, CancellationToken cancellationToken = default) =>
            inner.GetByCredentialIdAsync(id, cancellationToken);
        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
            inner.GetByUserIdAsync(userId, cancellationToken);
    }

    private static AuthenticatorAttestationRawResponse MakeResponse(CredentialCreateOptions options, byte[] id, out byte[] expectedPublicKey)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportParameters(false);
        var cose = new CborWriter();
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);
        cose.WriteInt32(3); cose.WriteInt32(-7);
        cose.WriteInt32(-1); cose.WriteInt32(1);
        cose.WriteInt32(-2); cose.WriteByteString(publicKey.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(publicKey.Q.Y!);
        cose.WriteEndMap();
        expectedPublicKey = cose.Encode();
        using var auth = new MemoryStream();
        auth.Write(SHA256.HashData(Encoding.UTF8.GetBytes("localhost")));
        auth.WriteByte(0x45); auth.Write(new byte[4]); auth.Write(new byte[16]);
        auth.WriteByte((byte)(id.Length >> 8)); auth.WriteByte((byte)id.Length);
        auth.Write(id); auth.Write(expectedPublicKey);
        var attestation = new CborWriter();
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(auth.ToArray());
        attestation.WriteEndMap();
        var client = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "webauthn.create", challenge = Base64Url(options.Challenge), origin = "http://localhost:4200"
        });
        var json = JsonSerializer.Serialize(new
        {
            id = Base64Url(id), rawId = Base64Url(id), type = "public-key",
            response = new { clientDataJSON = Base64Url(client), attestationObject = Base64Url(attestation.Encode()) }
        });
        return JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json)!;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

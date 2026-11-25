using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnAuthenticationCompletionTests
{
    [Fact]
    public async Task ValidAssertion_AuthenticatesAndRejectsReplay()
    {
        using var f = new Fixture();
        var operation = f.Options.Generate();
        var assertion = f.Response(operation.Options, counter: 1);
        Assert.Equal(f.UserId, await f.Completion.CompleteAsync(operation.OperationId, assertion));
        Assert.Equal(1u, f.Counter);
        Assert.Null(await f.Completion.CompleteAsync(operation.OperationId, assertion));
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("challenge")]
    [InlineData("origin")]
    [InlineData("rp")]
    [InlineData("credential")]
    [InlineData("user")]
    [InlineData("presence")]
    [InlineData("verification")]
    public async Task InvalidAssertion_IsRejectedAndConsumesOperation(string invalid)
    {
        using var f = new Fixture();
        var operation = f.Options.Generate();
        Assert.Null(await f.Completion.CompleteAsync(operation.OperationId, f.Response(operation.Options, invalid)));
        Assert.Null(await f.Completion.CompleteAsync(operation.OperationId, f.Response(operation.Options)));
        Assert.Equal(0u, f.Counter);
    }

    [Fact]
    public async Task ExpiredOperation_IsRejected()
    {
        using var f = new Fixture();
        var operation = f.Options.Generate();
        f.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Null(await f.Completion.CompleteAsync(operation.OperationId, f.Response(operation.Options)));
    }

    [Fact]
    public async Task ZeroCounter_IsAccepted_WhileNonIncreasingCounterIsRejected()
    {
        using var f = new Fixture();
        var first = f.Options.Generate();
        Assert.Equal(f.UserId, await f.Completion.CompleteAsync(first.OperationId, f.Response(first.Options)));
        var zeroAgain = f.Options.Generate();
        Assert.Equal(f.UserId, await f.Completion.CompleteAsync(zeroAgain.OperationId, f.Response(zeroAgain.Options)));
        var second = f.Options.Generate();
        Assert.Equal(f.UserId, await f.Completion.CompleteAsync(second.OperationId, f.Response(second.Options, counter: 2)));
        var third = f.Options.Generate();
        Assert.Null(await f.Completion.CompleteAsync(third.OperationId, f.Response(third.Options, counter: 2)));
        Assert.Equal(2u, f.Counter);
    }

    [Fact]
    public async Task ConcurrentSameOperation_OnlyOneSucceeds()
    {
        using var f = new Fixture();
        var operation = f.Options.Generate();
        var response = f.Response(operation.Options, counter: 1);
        var tasks = Enumerable.Range(0, 20).Select(_ => Task.Run(() => f.Completion.CompleteAsync(operation.OperationId, response)));
        Assert.Single(await Task.WhenAll(tasks), result => result == f.UserId);
    }

    [Fact]
    public async Task CounterUpdateConflict_RejectsVerifiedAssertion()
    {
        using var f = new Fixture { RejectUpdate = true };
        var operation = f.Options.Generate();
        Assert.Null(await f.Completion.CompleteAsync(operation.OperationId, f.Response(operation.Options, counter: 1)));
        Assert.Equal(0u, f.Counter);
    }

    internal sealed class Fixture : IDisposable, IWebAuthnCredentialRepository, IWebAuthnCounterRepository
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly MemoryCache _cache;
        private readonly byte[] _id = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _publicKey;
        private readonly string _origin;
        private readonly object _sync = new();
        public Guid UserId { get; }
        public TestClock Clock { get; } = new();
        public uint Counter { get; private set; }
        public bool RejectUpdate { get; set; }
        public WebAuthnAuthenticationOptionsService Options { get; }
        public WebAuthnAuthenticationCompletionService Completion { get; }
        private readonly Guid _credentialId = Guid.NewGuid();
        private readonly WebAuthnCredential _credential;

        public Fixture(string origin = "http://localhost:4200", Guid? userId = null)
        {
            UserId = userId ?? Guid.NewGuid();
            _origin = origin;
            var key = _key.ExportParameters(false);
            var cbor = new CborWriter();
            cbor.WriteStartMap(5);
            cbor.WriteInt32(1); cbor.WriteInt32(2);
            cbor.WriteInt32(3); cbor.WriteInt32(-7);
            cbor.WriteInt32(-1); cbor.WriteInt32(1);
            cbor.WriteInt32(-2); cbor.WriteByteString(key.Q.X!);
            cbor.WriteInt32(-3); cbor.WriteByteString(key.Q.Y!);
            cbor.WriteEndMap();
            _publicKey = cbor.Encode();
            _credential = new WebAuthnCredential(UserId, _id, _publicKey, 0);
            _credentialId = _credential.Id;
            _cache = new MemoryCache(new MemoryCacheOptions { Clock = Clock });
            var store = new WebAuthnAuthenticationStore(_cache);
            IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
            {
                RPID = "localhost", RPName = "SafeNet", ChallengeSize = 32,
                Origins = new HashSet<string> { origin }
            });
            Options = new WebAuthnAuthenticationOptionsService(fido, store);
            Completion = new WebAuthnAuthenticationCompletionService(fido, store, this, this);
        }

        public AuthenticatorAssertionRawResponse Response(AssertionOptions options, string? invalid = null, uint counter = 0)
            => MakeResponse(options, _key, _id, UserId, _origin, counter, invalid);

        internal static AuthenticatorAssertionRawResponse MakeResponse(AssertionOptions options, ECDsa key,
            byte[] credentialId, Guid userId, string origin, uint counter, string? invalid = null)
        {
            var id = invalid == "credential" ? RandomNumberGenerator.GetBytes(32) : credentialId;
            var auth = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(invalid == "rp" ? "wrong.example" : "localhost")).CopyTo(auth, 0);
            auth[32] = invalid == "presence" ? (byte)0x04 : invalid == "verification" ? (byte)0x01 : (byte)0x05;
            BinaryPrimitives.WriteUInt32BigEndian(auth.AsSpan(33), counter);
            var client = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get",
                challenge = B64(invalid == "challenge" ? RandomNumberGenerator.GetBytes(32) : options.Challenge),
                origin = invalid == "origin" ? "https://wrong.example" : origin
            });
            var signed = auth.Concat(SHA256.HashData(client)).ToArray();
            var signature = key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (invalid == "signature") signature[^1] ^= 1;
            var handle = invalid == "user" ? Guid.NewGuid().ToByteArray() : userId.ToByteArray();
            var json = JsonSerializer.Serialize(new
            {
                id = B64(id), rawId = B64(id), type = "public-key", clientExtensionResults = new { },
                response = new { authenticatorData = B64(auth), clientDataJSON = B64(client), signature = B64(signature), userHandle = B64(handle) }
            });
            return JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(json)!;
        }

        public Task<WebAuthnCredential?> GetByCredentialIdAsync(byte[] id, CancellationToken cancellationToken = default)
        {
            lock (_sync)
                return Task.FromResult<WebAuthnCredential?>(id.SequenceEqual(_id)
                    ? MakeSnapshot() : null);
        }
        private WebAuthnCredential MakeSnapshot()
        {
            // O ID de banco deve permanecer estável entre leituras; usa a entidade inicial para zero.
            return _credential;
        }
        public Task<bool> TryUpdateCounterAsync(Guid id, uint expectedCounter, uint newCounter, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                if (RejectUpdate || id != _credentialId || Counter != expectedCounter) return Task.FromResult(false);
                Counter = newCounter;
                typeof(WebAuthnCredential).GetProperty(nameof(WebAuthnCredential.SignatureCounter))!.SetValue(_credential, newCounter);
                return Task.FromResult(true);
            }
        }
        public Task AddAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public void Dispose() { _key.Dispose(); _cache.Dispose(); }
        private static string B64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    internal sealed class TestClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UtcNow;
        public void Advance(TimeSpan duration) => UtcNow += duration;
    }
}

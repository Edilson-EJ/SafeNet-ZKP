using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

public class WebAuthnRegistrationCompletionTests
{
    [Fact]
    public async Task ValidResponse_IsSavedForServerSideUser_AndCannotBeReplayed()
    {
        using var fixture = new Fixture();
        var (operation, options) = await fixture.Create();
        var response = MakeResponse(options);
        Assert.True(await fixture.Service.CompleteAsync(operation, fixture.Token, response));
        Assert.Equal(fixture.User.Id, Assert.Single(fixture.Repository.Saved).UserId);
        Assert.False(await fixture.Service.CompleteAsync(operation, fixture.Token, response));
        Assert.Single(fixture.Repository.Saved);
    }

    [Theory]
    [InlineData("challenge")]
    [InlineData("origin")]
    [InlineData("rp")]
    public async Task InvalidProtocolData_IsRejectedAndConsumesChallenge(string invalid)
    {
        using var fixture = new Fixture();
        var (operation, options) = await fixture.Create();
        Assert.False(await fixture.Service.CompleteAsync(operation, fixture.Token, MakeResponse(options, invalid)));
        Assert.False(await fixture.Service.CompleteAsync(operation, fixture.Token, MakeResponse(options)));
        Assert.Empty(fixture.Repository.Saved);
    }

    [Fact]
    public async Task WrongToken_CannotConsumeOperation()
    {
        using var fixture = new Fixture();
        var (operation, options) = await fixture.Create();
        var response = MakeResponse(options);
        Assert.False(await fixture.Service.CompleteAsync(operation, new string('0', 64), response));
        Assert.True(await fixture.Service.CompleteAsync(operation, fixture.Token, response));
    }

    [Fact]
    public async Task MalformedResponse_IsRejectedWithoutSaving()
    {
        using var fixture = new Fixture();
        var (operation, _) = await fixture.Create();
        var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>("{}")!;
        Assert.False(await fixture.Service.CompleteAsync(operation, fixture.Token, response));
        Assert.Empty(fixture.Repository.Saved);
    }

    [Fact]
    public async Task ConcurrentCompletion_OnlyOneSucceeds()
    {
        using var fixture = new Fixture();
        var (operation, options) = await fixture.Create();
        var response = MakeResponse(options);
        var tasks = Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
            fixture.Service.CompleteAsync(operation, fixture.Token, response))).ToArray();
        Assert.Single(await Task.WhenAll(tasks), success => success);
        Assert.Single(fixture.Repository.Saved);
    }

    [Fact]
    public async Task DuplicateCredential_IsRejected()
    {
        using var fixture = new Fixture();
        var id = RandomNumberGenerator.GetBytes(32);
        var (first, firstOptions) = await fixture.Create();
        Assert.True(await fixture.Service.CompleteAsync(first, fixture.Token, MakeResponse(firstOptions, id: id)));
        var (second, secondOptions) = await fixture.Create();
        Assert.False(await fixture.Service.CompleteAsync(second, fixture.Token, MakeResponse(secondOptions, id: id)));
        Assert.Single(fixture.Repository.Saved);
    }

    [Fact]
    public async Task PersistenceFailure_PropagatesAndChallengeCannotBeReused()
    {
        using var fixture = new Fixture();
        var (operation, options) = await fixture.Create();
        fixture.Repository.FailSave = true;
        var response = MakeResponse(options);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Service.CompleteAsync(operation, fixture.Token, response));
        fixture.Repository.FailSave = false;
        Assert.False(await fixture.Service.CompleteAsync(operation, fixture.Token, response));
        Assert.Empty(fixture.Repository.Saved);
    }

    private static AuthenticatorAttestationRawResponse MakeResponse(
        CredentialCreateOptions options, string? invalid = null, byte[]? id = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return MakeResponse(options, key, id ?? RandomNumberGenerator.GetBytes(32), "http://localhost:4200", invalid);
    }

    internal static AuthenticatorAttestationRawResponse MakeResponse(
        CredentialCreateOptions options, ECDsa key, byte[] id, string origin, string? invalid = null)
    {
        var publicKey = key.ExportParameters(false);
        var cose = new CborWriter();
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);
        cose.WriteInt32(3); cose.WriteInt32(-7);
        cose.WriteInt32(-1); cose.WriteInt32(1);
        cose.WriteInt32(-2); cose.WriteByteString(publicKey.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(publicKey.Q.Y!);
        cose.WriteEndMap();
        using var auth = new MemoryStream();
        auth.Write(SHA256.HashData(Encoding.UTF8.GetBytes(invalid == "rp" ? "wrong.example" : "localhost")));
        auth.WriteByte(0x45);
        auth.Write(new byte[4]);
        auth.Write(new byte[16]);
        auth.WriteByte((byte)(id.Length >> 8)); auth.WriteByte((byte)id.Length);
        auth.Write(id); auth.Write(cose.Encode());
        var attestation = new CborWriter();
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(auth.ToArray());
        attestation.WriteEndMap();
        var client = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "webauthn.create",
            challenge = Base64Url(invalid == "challenge" ? RandomNumberGenerator.GetBytes(32) : options.Challenge),
            origin = invalid == "origin" ? "https://wrong.example" : origin
        });
        var json = JsonSerializer.Serialize(new
        {
            id = Base64Url(id), rawId = Base64Url(id), type = "public-key",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = Base64Url(client), attestationObject = Base64Url(attestation.Encode()),
                transports = Array.Empty<string>()
            }
        });
        return JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(json)!;
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class Fixture : IDisposable
    {
        private readonly MemoryCache _cache = new(new MemoryCacheOptions());
        private readonly WebAuthnRegistrationOptionsService _options;
        public User User { get; } = new("Teste");
        public string Token { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        public Repository Repository { get; } = new();
        public WebAuthnRegistrationCompletionService Service { get; }
        public Fixture()
        {
            var store = new WebAuthnRegistrationStore(_cache);
            IFido2 fido = new Fido2NetLib.Fido2(new Fido2Configuration
            {
                RPID = "localhost", RPName = "SafeNet", Origins = new HashSet<string> { "http://localhost:4200" }, ChallengeSize = 32
            });
            _options = new WebAuthnRegistrationOptionsService(fido, Repository, store);
            Service = new WebAuthnRegistrationCompletionService(fido, store, Repository);
        }
        public Task<(Guid OperationId, CredentialCreateOptions Options)> Create() =>
            _options.GenerateAsync(User, completionToken: Token);
        public void Dispose() => _cache.Dispose();
    }

    private sealed class Repository : IWebAuthnCredentialRepository
    {
        public List<WebAuthnCredential> Saved { get; } = [];
        public bool FailSave { get; set; }
        public Task AddAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default)
        {
            if (FailSave) throw new InvalidOperationException("Falha simulada");
            Saved.Add(credential); return Task.CompletedTask;
        }
        public Task<WebAuthnCredential?> GetByCredentialIdAsync(byte[] id, CancellationToken cancellationToken = default) =>
            Task.FromResult(Saved.FirstOrDefault(c => c.CredentialId.SequenceEqual(id)));
        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<WebAuthnCredential>>(Saved.Where(c => c.UserId == id).ToList());
    }
}

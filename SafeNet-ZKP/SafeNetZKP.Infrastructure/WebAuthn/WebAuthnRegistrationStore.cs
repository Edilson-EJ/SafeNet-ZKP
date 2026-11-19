
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Cryptography;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnRegistrationStore
{
    private readonly IMemoryCache _cache;
    private readonly object _sync = new();

    private static readonly TimeSpan Expiration =
        TimeSpan.FromMinutes(5);

    public WebAuthnRegistrationStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public Guid Store(
        Guid userId,
        CredentialCreateOptions options,
        string? completionToken = null)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException(
                "O usuário é obrigatório.",
                nameof(userId));

        ArgumentNullException.ThrowIfNull(options);

        var operationId = Guid.NewGuid();

        var registration = new PendingRegistration(
            userId,
            options.ToJson(),
            completionToken is null ? null : HashToken(completionToken));

        _cache.Set(
            GetKey(operationId),
            registration,
            Expiration);

        return operationId;
    }

    public (Guid UserId, CredentialCreateOptions Options)? TakeAuthorized(
        Guid operationId, string? token)
    {
        if (operationId == Guid.Empty || token is not { Length: 64 } ||
            !token.All(Uri.IsHexDigit))
            return null;

        lock (_sync)
        {
            var key = GetKey(operationId);
            if (!_cache.TryGetValue<PendingRegistration>(key, out var registration) ||
                registration?.TokenHash is null ||
                !CryptographicOperations.FixedTimeEquals(registration.TokenHash, HashToken(token)))
                return null;

            _cache.Remove(key);
            return (registration.UserId, CredentialCreateOptions.FromJson(registration.OptionsJson));
        }
    }

    private static byte[] HashToken(string token) =>
        SHA256.HashData(Convert.FromHexString(token));

    public CredentialCreateOptions? Take(
        Guid operationId,
        Guid userId)
    {
        if (operationId == Guid.Empty ||
            userId == Guid.Empty)
            return null;

        var key = GetKey(operationId);

        lock (_sync)
        {
            if (!_cache.TryGetValue<PendingRegistration>(
                    key,
                    out var registration) ||
                registration is null ||
                registration.UserId != userId)
            {
                return null;
            }

            // Remove antes de verificar a resposta WebAuthn.
            _cache.Remove(key);

            return CredentialCreateOptions.FromJson(
                registration.OptionsJson);
        }
    }

    private static string GetKey(Guid operationId)
        => $"webauthn:registration:{operationId:N}";

    private sealed record PendingRegistration(
        Guid UserId,
        string OptionsJson,
        byte[]? TokenHash);
}

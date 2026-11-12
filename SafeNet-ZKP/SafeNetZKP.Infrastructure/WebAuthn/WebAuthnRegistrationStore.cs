
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;

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
        CredentialCreateOptions options)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException(
                "O usuário é obrigatório.",
                nameof(userId));

        ArgumentNullException.ThrowIfNull(options);

        var operationId = Guid.NewGuid();

        var registration = new PendingRegistration(
            userId,
            options.ToJson());

        _cache.Set(
            GetKey(operationId),
            registration,
            Expiration);

        return operationId;
    }

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
        string OptionsJson);
}

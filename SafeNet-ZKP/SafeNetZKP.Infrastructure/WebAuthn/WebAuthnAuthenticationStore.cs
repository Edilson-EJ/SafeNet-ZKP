using System.Security.Cryptography;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;

namespace SafeNetZKP.Infrastructure.WebAuthn;

// Um singleton por processo: o lock garante consumo atômico neste processo.
public sealed class WebAuthnAuthenticationStore(IMemoryCache cache)
{
    private static readonly TimeSpan Expiration = TimeSpan.FromMinutes(5);
    private readonly object _sync = new();

    public string Store(AssertionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var operationId = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        cache.Set(Key(operationId), options.ToJson(), Expiration);
        return operationId;
    }

    // Chamar antes de verificar a resposta, inclusive para tentativas inválidas.
    public AssertionOptions? Take(string? operationId)
    {
        if (operationId is not { Length: 64 } || !operationId.All(Uri.IsHexDigit))
            return null;

        lock (_sync)
        {
            var key = Key(operationId);
            if (!cache.TryGetValue<string>(key, out var json) || json is null)
                return null;
            cache.Remove(key);
            return AssertionOptions.FromJson(json);
        }
    }

    private static string Key(string operationId) =>
        $"webauthn:authentication:{Convert.ToHexString(SHA256.HashData(Convert.FromHexString(operationId)))}";
}


using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Application.Interfaces.Security;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnEnrollmentTicketStore  : IEnrollmentTicketIssuer
{
    private static readonly TimeSpan Expiration =
        TimeSpan.FromMinutes(10);

    private readonly IMemoryCache _cache;
    private readonly object _sync = new();

    public WebAuthnEnrollmentTicketStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public string Issue(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(
                "O usuário é obrigatório.",
                nameof(userId));
        }

        // Gera um token aleatório de 256 bits.
        var token = Convert.ToHexString(
            RandomNumberGenerator.GetBytes(32));

        // Armazena o usuário associado ao token.
        _cache.Set(
            GetKey(token),
            userId,
            Expiration);

        return token;
    }

    public Guid? TryGetUserId(string? token)
    {
        if (!IsValidToken(token))
            return null;

        var key = GetKey(token!);

        if (!_cache.TryGetValue<Guid>(key, out var userId))
            return null;

        return userId == Guid.Empty ? null : userId;
    }

    public bool Consume(string? token, Guid userId)
    {
        if (!IsValidToken(token) || userId == Guid.Empty)
            return false;

        var key = GetKey(token!);

        lock (_sync)
        {
            if (!_cache.TryGetValue<Guid>(key, out var storedUserId))
                return false;

            if (storedUserId != userId)
                return false;

            // Impede reutilização do token.
            _cache.Remove(key);

            return true;
        }
    }

    private static bool IsValidToken(string? token)
    {
        return token is { Length: 64 }
            && token.All(Uri.IsHexDigit);
    }

    private static string GetKey(string token)
    {
        // Não utiliza o token original como chave do cache.
        var tokenBytes = Convert.FromHexString(token);
        var hash = SHA256.HashData(tokenBytes);

        return $"webauthn:enrollment:{Convert.ToHexString(hash)}";
    }
}

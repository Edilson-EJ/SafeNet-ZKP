using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SafeNetZKP.Api.Security;

public sealed class GatewayObservationAuthentication(IConfiguration configuration, TimeProvider clock)
{
    public const int MaxBodyBytes = 2048;
    private const int ClockSkewSeconds = 60;
    private const int ObservationLifetimeSeconds = 120;

    internal bool TryAuthenticate(IHeaderDictionary headers, ReadOnlySpan<byte> body,
        out AuthenticatedGatewayMessage message)
    {
        message = default;
        var gateway = SingleHeader(headers, "X-SafeNet-Gateway");
        var timestamp = SingleHeader(headers, "X-SafeNet-Timestamp");
        var nonce = SingleHeader(headers, "X-SafeNet-Nonce");
        var signature = SingleHeader(headers, "X-SafeNet-Signature");
        if (!Guid.TryParseExact(gateway, "D", out var gatewayId) || gatewayId == Guid.Empty ||
            gateway != gatewayId.ToString("D") ||
            !long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ||
            timestamp != seconds.ToString(CultureInfo.InvariantCulture) ||
            !IsLowerHex(nonce, 32) || !IsLowerHex(signature, 64))
            return false;

        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (seconds < now - ClockSkewSeconds || seconds > now + ClockSkewSeconds)
            return false;

        var secret = configuration[$"CaptivePortal:GatewayKeys:{gateway}"];
        var key = new byte[32];
        try
        {
            if (secret is not { Length: 44 } ||
                !Convert.TryFromBase64String(secret, key, out var written) || written != key.Length)
                return false;

            var bodyHash = Convert.ToHexStringLower(SHA256.HashData(body));
            var payload = Encoding.ASCII.GetBytes(
                $"safenet-gateway-observation-v1\nPOST\n/api/captive-portal/gateway/observations\n{gateway}\n{timestamp}\n{nonce}\n{bodyHash}");
            var expected = HMACSHA256.HashData(key, payload);
            if (!CryptographicOperations.FixedTimeEquals(expected, Convert.FromHexString(signature!)))
                return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        var observedAt = DateTimeOffset.FromUnixTimeSeconds(seconds);
        message = new AuthenticatedGatewayMessage(gatewayId, nonce!, observedAt,
            observedAt.AddSeconds(ObservationLifetimeSeconds));
        return true;
    }

    private static string? SingleHeader(IHeaderDictionary headers, string name) =>
        headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;

    private static bool IsLowerHex(string? value, int length) =>
        value?.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal readonly record struct AuthenticatedGatewayMessage(Guid GatewayId, string Nonce,
    DateTimeOffset ObservedAt, DateTimeOffset ExpiresAt);

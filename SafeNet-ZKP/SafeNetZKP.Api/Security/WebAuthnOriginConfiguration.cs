namespace SafeNetZKP.Api.Security;

internal static class WebAuthnOriginConfiguration
{
    public static bool IsValidRpId(string rpId) =>
        Uri.CheckHostName(rpId) == UriHostNameType.Dns &&
        !rpId.EndsWith('.') &&
        rpId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');

    public static bool IsAllowedOrigin(string origin, string rpId)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.HostNameType != UriHostNameType.Dns)
            return false;

        var host = uri.IdnHost;
        var canonical = uri.IsDefaultPort ? $"https://{host}" : $"https://{host}:{uri.Port}";
        return string.Equals(origin, canonical, StringComparison.OrdinalIgnoreCase) &&
            (host.Equals(rpId, StringComparison.OrdinalIgnoreCase) ||
             host.EndsWith("." + rpId, StringComparison.OrdinalIgnoreCase));
    }
}

using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Api.Services;

// Only trusted in-process ingress may register an observation for a verified web session.
// There is no production or HTTP producer for this registry.
public sealed class CaptivePortalIngress(TimeProvider clock) : IDisposable
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions { SizeLimit = 1024 });
    private readonly object _observations = new();

    public void StageObservation(string verifiedSessionId, ObservedNetworkConnection observation,
        string gatewayReference, DateTimeOffset referenceExpiresAt)
    {
        if (!IsReference(verifiedSessionId) || !IsReference(gatewayReference))
            throw new ArgumentException("Invalid trusted ingress context.");

        var expiresAt = referenceExpiresAt < observation.ExpiresAt ? referenceExpiresAt : observation.ExpiresAt;
        var key = Hash(gatewayReference);
        lock (_observations)
        {
            if (_cache.TryGetValue<StagedObservation>(key, out _))
                throw new InvalidOperationException("A gateway reference is already staged.");
            Store(key, new StagedObservation(Hash(verifiedSessionId), observation, expiresAt), expiresAt);
        }
    }

    internal ObservedNetworkConnection? FindObservation(string sessionId, string reference) =>
        IsReference(reference) && _cache.Get<StagedObservation>(Hash(reference)) is { } staged &&
        staged.ExpiresAt > clock.GetUtcNow() && staged.SessionHash == Hash(sessionId) ? staged.Observation : null;

    internal void CompleteAssociation(string sessionId, string reference, PersistentNetworkAccessBinding binding)
    {
        _cache.Remove(Hash(reference));
        Store((Hash(sessionId), binding.Id), binding, binding.ExpiresAt);
    }

    internal PersistentNetworkAccessBinding? FindBinding(string sessionId, Guid id) =>
        _cache.Get<PersistentNetworkAccessBinding>((Hash(sessionId), id)) is { } binding &&
        binding.ExpiresAt > clock.GetUtcNow() ? binding : null;

    private void Store<T>(object key, T value, DateTimeOffset expiresAt) where T : class
    {
        var lifetime = expiresAt - clock.GetUtcNow();
        if (lifetime > TimeSpan.Zero)
            _cache.Set(key, value, new MemoryCacheEntryOptions
            {
                Size = 1,
                AbsoluteExpirationRelativeToNow = lifetime
            });
    }

    private static bool IsReference(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Convert.FromHexString(value)));

    public void Dispose() => _cache.Dispose();

    private sealed record StagedObservation(string SessionHash, ObservedNetworkConnection Observation,
        DateTimeOffset ExpiresAt);
}

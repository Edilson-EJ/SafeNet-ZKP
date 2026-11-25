using System.Collections.Concurrent;
using System.Data.Common;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed partial class CaptivePortalHttpTests
{
    private const string GatewayPath = Root + "/gateway/observations";

    [Fact]
    public async Task AuthorizedGatewayCanRecordObservationButBrowserCannotAssociateIt()
    {
        using var lab = new GatewayLab();
        using var session = await lab.Host.SignInAsync();
        using var report = lab.Report();
        using var accepted = await lab.Client.SendAsync(report);
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        var recorded = Assert.Single(lab.Store.Records);
        Assert.Equal(lab.Gateway, recorded.GatewayId);
        Assert.Equal(lab.Connection, recorded.ConnectionId);
        Assert.Equal(1, recorded.Generation);
        Assert.Equal(TimeSpan.FromMinutes(2), recorded.ExpiresAt - recorded.ObservedAt);

        // Even knowledge of gateway metadata and valid portal CSRF grants no association.
        var fabricatedReference = $"{recorded.ConnectionId:N}{recorded.Nonce}";
        using var fabricated = await session.Client.PostAsJsonAsync(Root + "/associations",
            new AssociateConnectionRequest(fabricatedReference));
        Assert.Equal(HttpStatusCode.NotFound, fabricated.StatusCode);
        using var cookieOnly = await session.Client.PostAsJsonAsync(GatewayPath,
            new { gatewayId = lab.Gateway, connectionId = lab.Connection, generation = 1 });
        Assert.Equal(HttpStatusCode.Unauthorized, cookieOnly.StatusCode);
        Assert.Single(lab.Store.Records);
    }

    [Theory]
    [InlineData("unknown", HttpStatusCode.Unauthorized)]
    [InlineData("invalid-key", HttpStatusCode.Unauthorized)]
    [InlineData("modified-body", HttpStatusCode.Unauthorized)]
    [InlineData("expired", HttpStatusCode.Unauthorized)]
    [InlineData("future", HttpStatusCode.Unauthorized)]
    [InlineData("other-gateway", HttpStatusCode.Forbidden)]
    [InlineData("http", HttpStatusCode.Forbidden)]
    public async Task InvalidGatewayReportCannotReachPersistence(string scenario, HttpStatusCode status)
    {
        using var lab = new GatewayLab();
        var other = Guid.NewGuid();
        using var report = lab.Report(
            sender: scenario == "unknown" ? other : null,
            claimedGateway: scenario == "other-gateway" ? other : null,
            signedWith: scenario == "invalid-key" ? RandomNumberGenerator.GetBytes(32) : null,
            timestampOffset: scenario switch { "expired" => -61, "future" => 61, _ => 0 },
            alterBody: scenario == "modified-body", plainHttp: scenario == "http");
        using var response = await lab.Client.SendAsync(report);
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(0, lab.Store.Attempts);
        Assert.Empty(lab.Store.Records);
    }

    [Fact]
    public async Task SameNonceIsConsumedOnceEvenAcrossConcurrentRequests()
    {
        using var lab = new GatewayLab();
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        async Task<HttpStatusCode> SendAsync()
        {
            using var request = lab.Report(nonce: nonce);
            using var response = await lab.Client.SendAsync(request);
            return response.StatusCode;
        }

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => SendAsync()));
        Assert.Single(results, status => status == HttpStatusCode.NoContent);
        Assert.Equal(5, results.Count(status => status == HttpStatusCode.Conflict));
        Assert.Equal(HttpStatusCode.Conflict, await SendAsync());
        Assert.Single(lab.Store.Records);
    }

    [Fact]
    public async Task ReplayStoreFailureCannotAcceptObservation()
    {
        using var lab = new GatewayLab();
        lab.Store.Unavailable = true;
        using var report = lab.Report();
        using var response = await lab.Client.SendAsync(report);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, lab.Store.Attempts);
        Assert.Empty(lab.Store.Records);
    }

    [Fact]
    public async Task GatewayRouteIsAbsentInProduction()
    {
        using var lab = new GatewayLab("Production");
        using var report = lab.Report();
        using var response = await lab.Client.SendAsync(report);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, lab.Store.Attempts);
    }

    private sealed class GatewayLab : IDisposable
    {
        private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
        private readonly PortalTestClock _clock = new();
        public Guid Gateway { get; } = Guid.NewGuid();
        public Guid Connection { get; } = Guid.NewGuid();
        public ObservationStore Store { get; } = new();
        public Api Host { get; }
        public HttpClient Client { get; }

        public GatewayLab(string environment = "Development")
        {
            Host = new Api(environment, clock: _clock, configure: builder =>
            {
                builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        [$"CaptivePortal:GatewayKeys:{Gateway:D}"] = Convert.ToBase64String(_secret)
                    }));
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<IGatewayObservationRepository>();
                    services.AddSingleton<IGatewayObservationRepository>(Store);
                });
            });
            Client = Host.Client();
        }

        public HttpRequestMessage Report(string? nonce = null, Guid? sender = null, Guid? claimedGateway = null,
            byte[]? signedWith = null, int timestampOffset = 0, bool alterBody = false, bool plainHttp = false)
        {
            var timestamp = (_clock.GetUtcNow().ToUnixTimeSeconds() + timestampOffset).ToString(CultureInfo.InvariantCulture);
            var gateway = (sender ?? Gateway).ToString("D");
            nonce ??= Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var body = JsonSerializer.SerializeToUtf8Bytes(new { gatewayId = claimedGateway ?? sender ?? Gateway,
                connectionId = Connection, generation = 1 });
            var digest = Convert.ToHexStringLower(SHA256.HashData(body));
            var canonical = string.Join('\n', "safenet-gateway-observation-v1", "POST", GatewayPath,
                gateway, timestamp, nonce, digest);
            var signature = HMACSHA256.HashData(signedWith ?? _secret, Encoding.ASCII.GetBytes(canonical));

            if (alterBody)
                body = JsonSerializer.SerializeToUtf8Bytes(new { gatewayId = Gateway, connectionId = Connection, generation = 2 });
            var request = new HttpRequestMessage(HttpMethod.Post, plainHttp ? "http://localhost" + GatewayPath : GatewayPath)
            {
                Content = new ByteArrayContent(body)
            };
            request.Content.Headers.ContentType = new("application/json");
            request.Headers.Add("X-SafeNet-Gateway", gateway);
            request.Headers.Add("X-SafeNet-Timestamp", timestamp);
            request.Headers.Add("X-SafeNet-Nonce", nonce);
            request.Headers.Add("X-SafeNet-Signature", Convert.ToHexStringLower(signature));
            return request;
        }

        public void Dispose()
        {
            Client.Dispose();
            Host.Dispose();
            CryptographicOperations.ZeroMemory(_secret);
        }
    }

    private sealed class ObservationStore : IGatewayObservationRepository
    {
        private readonly ConcurrentDictionary<(Guid Gateway, string Nonce), GatewayObservation> _records = new();
        private int _attempts;
        public int Attempts => Volatile.Read(ref _attempts);
        public IEnumerable<GatewayObservation> Records => _records.Values;
        public bool Unavailable { get; set; }

        public Task<bool> TryRecordAsync(GatewayObservation observation, CancellationToken ct)
        {
            Interlocked.Increment(ref _attempts);
            if (Unavailable)
                throw new ReplayStoreUnavailableException();
            return Task.FromResult(_records.TryAdd((observation.GatewayId, observation.Nonce), observation));
        }
    }

    private sealed class ReplayStoreUnavailableException : DbException;
}

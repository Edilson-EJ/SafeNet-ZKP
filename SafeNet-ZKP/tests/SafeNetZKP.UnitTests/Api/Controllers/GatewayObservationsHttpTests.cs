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
using Microsoft.Extensions.Logging;
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

    [Fact]
    public async Task SharedGatewayKeyCannotAuthenticateEitherConfiguredIdentity()
    {
        using var lab = new GatewayLab(duplicateKey: true);
        using var first = lab.Report();
        using var second = lab.Report(sender: lab.OtherGateway);
        using var firstResult = await lab.Client.SendAsync(first);
        using var secondResult = await lab.Client.SendAsync(second);
        Assert.Equal(HttpStatusCode.Unauthorized, firstResult.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondResult.StatusCode);
        Assert.Equal(0, lab.Store.Attempts);
    }

    [Fact]
    public async Task GatewayCredentialRevocationAndRotationPreserveReplayHistoryAndExistingOperations()
    {
        using var lab = new GatewayLab();
        using var owner = await lab.Host.SignInAsync();
        var binding = await AssociateAsync(owner, lab.Host.Stage(owner));
        using var authorization = await AuthorizeAsync(owner, binding, Guid.NewGuid());
        var operation = await ReadAsync(authorization, HttpStatusCode.OK, "authorized");
        var location = Root + $"/operations/{operation.OperationId}";
        var originalNonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var replacementKey = RandomNumberGenerator.GetBytes(32);
        var otherKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            async Task<HttpStatusCode> SubmitAsync(HttpRequestMessage report)
            {
                using (report)
                using (var response = await lab.Client.SendAsync(report))
                    return response.StatusCode;
            }

            Assert.Equal(HttpStatusCode.NoContent, await SubmitAsync(lab.Report(nonce: originalNonce)));
            lab.SetKey(lab.Gateway, null);
            Assert.Equal(HttpStatusCode.Unauthorized, await SubmitAsync(lab.Report()));
            Assert.Single(lab.Store.Records);

            using var existing = await owner.Client.GetAsync(location);
            await ReadAsync(existing, HttpStatusCode.OK, "authorized");
            Assert.Equal(1, lab.Host.Network.OperationCount);

            lab.SetKey(lab.Gateway, replacementKey);
            lab.SetKey(lab.OtherGateway, otherKey);
            Assert.Equal(HttpStatusCode.Unauthorized, await SubmitAsync(lab.Report()));
            Assert.Equal(HttpStatusCode.Unauthorized,
                await SubmitAsync(lab.Report(sender: lab.OtherGateway, signedWith: replacementKey)));
            Assert.Equal(HttpStatusCode.Conflict,
                await SubmitAsync(lab.Report(nonce: originalNonce, signedWith: replacementKey)));
            Assert.Equal(HttpStatusCode.NoContent,
                await SubmitAsync(lab.Report(signedWith: replacementKey)));
            Assert.Equal(HttpStatusCode.NoContent,
                await SubmitAsync(lab.Report(sender: lab.OtherGateway, signedWith: otherKey, nonce: originalNonce)));
            Assert.Equal(3, lab.Store.Records.Count());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(replacementKey);
            CryptographicOperations.ZeroMemory(otherKey);
        }
    }

    [Fact]
    public async Task GatewayAuditDistinguishesReplayWithoutLoggingCredentials()
    {
        using var logs = new AuditProbe();
        using var lab = new GatewayLab(logs: logs);
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var cookie = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var first = lab.Report(nonce: nonce);
        first.Headers.Add("Cookie", $"__Host-SafeNetZKP={cookie}");
        using var accepted = await lab.Client.SendAsync(first);
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        using var duplicate = lab.Report(nonce: nonce);
        using var replay = await lab.Client.SendAsync(duplicate);
        Assert.Equal(HttpStatusCode.Conflict, replay.StatusCode);
        var fields = await logs.Replay.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("GatewayObservations", fields["Controller"]);
        Assert.Equal("Record", fields["Action"]);
        Assert.NotNull(fields["TraceId"]);
        var signature = Assert.Single(first.Headers.GetValues("X-SafeNet-Signature"));
        Assert.All(logs.Messages, message =>
        {
            Assert.DoesNotContain(nonce, message);
            Assert.DoesNotContain(cookie, message);
            Assert.DoesNotContain(signature, message);
            Assert.DoesNotContain(lab.EncodedKey, message);
        });
    }

    private sealed class GatewayLab : IDisposable
    {
        private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
        private readonly PortalTestClock _clock = new();
        public Guid Gateway { get; } = Guid.NewGuid();
        public Guid OtherGateway { get; } = Guid.NewGuid();
        public Guid Connection { get; } = Guid.NewGuid();
        public ObservationStore Store { get; } = new();
        public Api Host { get; }
        public HttpClient Client { get; }
        public string EncodedKey => Convert.ToBase64String(_secret);

        public void SetKey(Guid gateway, byte[]? key) =>
            Host.Services.GetRequiredService<IConfiguration>()[$"CaptivePortal:GatewayKeys:{gateway:D}"] =
                key is null ? null : Convert.ToBase64String(key);

        public GatewayLab(string environment = "Development", ILoggerProvider? logs = null, bool duplicateKey = false)
        {
            Host = new Api(environment, clock: _clock, configure: builder =>
            {
                if (logs is not null)
                    builder.ConfigureLogging(logging => logging.AddProvider(logs));
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    var keys = new Dictionary<string, string?>
                    {
                        [$"CaptivePortal:GatewayKeys:{Gateway:D}"] = Convert.ToBase64String(_secret)
                    };
                    if (duplicateKey)
                        keys[$"CaptivePortal:GatewayKeys:{OtherGateway:D}"] = Convert.ToBase64String(_secret);
                    config.AddInMemoryCollection(keys);
                });
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

    private sealed class AuditProbe : ILoggerProvider, ILogger
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public TaskCompletionSource<IReadOnlyDictionary<string, object?>> Replay { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Dispose() { }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Enqueue(formatter(state, exception));
            if (state is IReadOnlyList<KeyValuePair<string, object?>> fields &&
                fields.Any(field => field is { Key: "Controller", Value: "GatewayObservations" }) &&
                fields.Any(field => field is { Key: "StatusCode", Value: 409 }))
                Replay.TrySetResult(fields.ToDictionary(field => field.Key, field => field.Value));
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

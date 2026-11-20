using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.UnitTests.Api.Security;
using SafeNetZKP.UnitTests.Infrastructure.WebAuthn;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public sealed class EndpointAuthorizationTests
{
    private const string Origin = "https://localhost";

    [Theory]
    [InlineData("GET", "/api/auth/me")]
    [InlineData("GET", "/api/auth/csrf")]
    [InlineData("POST", "/api/auth/logout")]
    [InlineData("POST", "/api/users")]
    [InlineData("GET", "/api/users/00000000-0000-0000-0000-000000000001")]
    public async Task PrivateEndpoints_ChallengeWithoutSession(string method, string path)
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task WebAuthnSignIn_AllowsOwnAccountAndSessionButHidesOtherAccounts()
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        using var health = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        await SignInAsync(api, client);
        var me = await client.GetFromJsonAsync<SessionUserResponse>("/api/auth/me");
        Assert.Equal(new SessionUserResponse(api.Owner.Id, api.Owner.Name), me);
        using var ownAccount = await client.GetAsync($"/api/users/{api.Owner.Id}");
        Assert.Equal(HttpStatusCode.OK, ownAccount.StatusCode);
        var account = await ownAccount.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(api.Owner.Id, account.GetProperty("id").GetGuid());
        Assert.Equal(api.Owner.Name, account.GetProperty("name").GetString());

        api.Users.Reads.Clear();
        using var otherAccount = await client.GetAsync($"/api/users/{api.Other.Id}");
        using var missingAccount = await client.GetAsync($"/api/users/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, otherAccount.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missingAccount.StatusCode);
        Assert.Empty(api.Users.Reads);
    }

    [Fact]
    public async Task StateChanges_RequireCsrf_AndLogoutClearsSession()
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        await SignInAsync(api, client);
        var csrf = await client.GetFromJsonAsync<CsrfTokenResponse>("/api/auth/csrf");
        Assert.NotNull(csrf);

        using var missingCreate = await client.PostAsJsonAsync("/api/users", new { name = "New account" });
        using var missingLogout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.BadRequest, missingCreate.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, missingLogout.StatusCode);

        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", "invalid");
        using var invalidCreate = await client.PostAsJsonAsync("/api/users", new { name = "New account" });
        using var invalidLogout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.BadRequest, invalidCreate.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalidLogout.StatusCode);
        Assert.Equal(2, api.Users.Count);
        Assert.NotNull(await client.GetFromJsonAsync<SessionUserResponse>("/api/auth/me"));

        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf.Token);
        using var created = await client.PostAsJsonAsync("/api/users", new { name = "New account" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(3, api.Users.Count);

        using var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var afterLogout = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
    }

    [Fact]
    public async Task Logout_RejectsOldCookieAndKeepsSecondSessionActive()
    {
        using var api = new Api();
        using var first = api.CreateHttpsClient();
        using var second = api.CreateHttpsClient();
        var originalCookie = await SignInAsync(api, first);
        await SignInAsync(api, second);
        var csrf = await first.GetFromJsonAsync<CsrfTokenResponse>("/api/auth/csrf");
        Assert.NotNull(csrf);
        first.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf.Token);
        using var logout = await first.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var replayClient = api.CreateHttpsClient();
        replayClient.DefaultRequestHeaders.Add("Cookie", originalCookie);
        using var replay = await replayClient.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(new SessionUserResponse(api.Owner.Id, api.Owner.Name),
            await second.GetFromJsonAsync<SessionUserResponse>("/api/auth/me"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("expired")]
    [InlineData("wrong-owner")]
    [InlineData("revoked")]
    [InlineData("unavailable")]
    [InlineData("invalid")]
    [InlineData("tampered")]
    public async Task InvalidSessionOrCookie_IsRejectedOverHttpPipeline(string state)
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        var id = RandomNumberGenerator.GetBytes(32);
        var hash = SHA256.HashData(id);
        var now = DateTime.UtcNow;
        if (state != "missing")
        {
            var owner = state == "wrong-owner" ? api.Other.Id : api.Owner.Id;
            var expires = state == "expired" ? now.AddMinutes(-1) : now.AddMinutes(20);
            await api.Sessions.AddAsync(new(hash, owner, now.AddMinutes(-2), expires), CancellationToken.None);
            if (state == "revoked")
                await api.Sessions.RevokeAsync(hash, owner, now, CancellationToken.None);
        }
        api.Sessions.FailReads = state == "unavailable";
        var properties = new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(20) };
        properties.SetString(SafeNetCookieAuthentication.SessionIdKey, Convert.ToHexString(id));
        var value = ProtectTicket(api, api.Owner.Id, properties);
        if (state == "tampered")
            value = value[..20] + (value[20] == 'A' ? 'B' : 'A') + value[21..];
        if (state == "invalid")
            value = "invalid";
        client.DefaultRequestHeaders.Add("Cookie", $"__Host-SafeNetZKP={value}");
        using var response = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(api.Users.Reads);
    }

    [Theory]
    [InlineData("GET", "/api/auth/me")]
    [InlineData("GET", "/api/auth/csrf")]
    [InlineData("POST", "/api/auth/logout")]
    [InlineData("GET", "/api/users/00000000-0000-0000-0000-000000000001")]
    [InlineData("POST", "/api/users")]
    [InlineData("POST", "/api/webauthn/authentication/options")]
    [InlineData("POST", "/api/webauthn/authentication/complete")]
    [InlineData("POST", "/api/webauthn/enrollment/start")]
    [InlineData("POST", "/api/webauthn/enrollment/options")]
    [InlineData("POST", "/api/webauthn/enrollment/complete")]
    public async Task SensitiveRoutes_RejectPlainHttp(string method, string path)
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        using var request = new HttpRequestMessage(new HttpMethod(method), "http://localhost" + path);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task DevelopmentHealthProbe_RemainsAvailableOverHttp()
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        using var response = await client.GetAsync("http://localhost/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void WebAuthnConfiguration_RejectsAnHttpOrigin()
    {
        using var api = new Api(configuredOrigin: "http://localhost");
        Assert.Throws<InvalidOperationException>(() => api.CreateHttpsClient());
    }

    [Fact]
    public async Task SessionWriteFailure_IssuesNoAuthenticationCookie()
    {
        using var api = new Api();
        using var client = api.CreateHttpsClient();
        api.Sessions.FailWrites = true;
        using var result = await CompleteSignInAsync(api, client);
        Assert.Equal(HttpStatusCode.InternalServerError, result.StatusCode);
        Assert.False(result.Headers.Contains("Set-Cookie"));
        Assert.Empty(api.Sessions.Sessions);
        using var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Logout_RejectsCsrfTokenFromAnotherIdentity()
    {
        using var api = new Api();
        using var first = api.CreateHttpsClient();
        using var second = api.CreateHttpsClient();
        await SignInAsync(api, first);
        using var csrfResponse = await first.GetAsync("/api/auth/csrf");
        Assert.Equal(HttpStatusCode.OK, csrfResponse.StatusCode);
        var csrf = await csrfResponse.Content.ReadFromJsonAsync<CsrfTokenResponse>();
        Assert.NotNull(csrf);
        var csrfCookie = csrfResponse.Headers.GetValues("Set-Cookie")
            .Single(header => header.StartsWith("__Host-SafeNetZKP-CSRF=", StringComparison.Ordinal)).Split(';')[0];

        using var scope = api.Services.CreateScope();
        var properties = await InMemorySessionRepository.IssueAsync(scope.ServiceProvider, api.Other.Id);
        var otherTicket = ProtectTicket(api, api.Other.Id, properties);
        second.DefaultRequestHeaders.Add("Cookie", $"__Host-SafeNetZKP={otherTicket}; {csrfCookie}");
        second.DefaultRequestHeaders.Add("X-CSRF-TOKEN", csrf.Token);
        using var logout = await second.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.BadRequest, logout.StatusCode);
        Assert.Equal(new SessionUserResponse(api.Other.Id, api.Other.Name),
            await second.GetFromJsonAsync<SessionUserResponse>("/api/auth/me"));
    }

    [Fact]
    public async Task AuthenticatedUser_CannotCreateAccountsInProduction()
    {
        using var api = new Api("Production");
        using var client = api.CreateHttpsClient();
        const string scheme = CookieAuthenticationDefaults.AuthenticationScheme;
        var cookie = api.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
        using var scope = api.Services.CreateScope();
        var ticket = new AuthenticationTicket(SafeNetCookieAuthentication.CreatePrincipal(api.Owner.Id),
            await InMemorySessionRepository.IssueAsync(scope.ServiceProvider, api.Owner.Id), scheme);
        client.DefaultRequestHeaders.Add("Cookie", $"{cookie.Cookie.Name}={cookie.TicketDataFormat.Protect(ticket)}");

        using var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        using var denied = await client.PostAsJsonAsync("/api/users", new { name = "Blocked account" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Null(denied.Headers.Location);
        Assert.Equal(2, api.Users.Count);
    }

    [Theory]
    [InlineData("Development", HttpStatusCode.OK)]
    [InlineData("Production", HttpStatusCode.ServiceUnavailable)]
    public async Task ExperimentalEnrollment_StartsWithoutSessionOnlyInDevelopment(string environment, HttpStatusCode status)
    {
        using var api = new Api(environment);
        using var client = api.CreateHttpsClient();
        using var response = await client.PostAsJsonAsync("/api/webauthn/enrollment/start", new { name = "Passkey account" });
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(environment == "Development" ? 3 : 2, api.Users.Count);
    }

    private static async Task<string> SignInAsync(Api api, HttpClient client)
    {
        using var result = await CompleteSignInAsync(api, client);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        var cookie = result.Headers.GetValues("Set-Cookie")
            .SingleOrDefault(header => header.StartsWith("__Host-SafeNetZKP=", StringComparison.Ordinal));
        return (cookie ?? throw new InvalidOperationException("Authentication cookie missing.")).Split(';')[0];
    }

    private static async Task<HttpResponseMessage> CompleteSignInAsync(Api api, HttpClient client)
    {
        using var start = await client.PostAsync("/api/webauthn/authentication/options", null);
        Assert.Equal(HttpStatusCode.OK, start.StatusCode);
        var challenge = await start.Content.ReadFromJsonAsync<AuthenticationOptionsResponse>();
        Assert.NotNull(challenge);
        var options = AssertionOptions.FromJson(challenge.Options.GetRawText());
        using var complete = new HttpRequestMessage(HttpMethod.Post, "/api/webauthn/authentication/complete")
        {
            Content = JsonContent.Create(new AuthenticationCompletionRequest
            {
                OperationId = challenge.OperationId,
                Response = api.Passkey.Response(options, counter: api.Passkey.Counter + 1)
            })
        };
        complete.Headers.Add("Origin", Origin);
        return await client.SendAsync(complete);
    }

    private static string ProtectTicket(Api api, Guid userId, AuthenticationProperties properties)
    {
        const string scheme = CookieAuthenticationDefaults.AuthenticationScheme;
        var options = api.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
        return options.TicketDataFormat.Protect(
            new AuthenticationTicket(SafeNetCookieAuthentication.CreatePrincipal(userId), properties, scheme));
    }

    private sealed class Api : WebApplicationFactory<Program>
    {
        private readonly string _environment;
        private readonly string _configuredOrigin;

        public Api(string environment = "Development", string configuredOrigin = Origin)
        {
            _environment = environment;
            _configuredOrigin = configuredOrigin;
            Users = new UserRepository(Owner, Other);
            Passkey = new(Origin, Owner.Id);
        }

        public User Owner { get; } = new("Session owner");
        public User Other { get; } = new("Other user");
        public UserRepository Users { get; }
        public InMemorySessionRepository Sessions { get; } = new();
        public WebAuthnAuthenticationCompletionTests.Fixture Passkey { get; }

        public HttpClient CreateHttpsClient() => CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(Origin),
            AllowAutoRedirect = false
        });

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(config => config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Fido2:RPID"] = "localhost",
                    ["Fido2:RPName"] = "SafeNet Tests",
                    ["Fido2:Origins:0"] = _configuredOrigin,
                    ["ConnectionStrings:DefaultConnection"] = ""
                }));
            return base.CreateHost(builder);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(_environment);
            builder.ConfigureServices(services =>
            {
                var eventLog = services.SingleOrDefault(
                    service => service.ServiceType == typeof(ILoggerProvider) &&
                        service.ImplementationType == typeof(EventLogLoggerProvider));
                if (eventLog is not null)
                    services.Remove(eventLog);
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                services.RemoveAll<IAuthenticatedSessionRepository>();
                services.AddSingleton<IAuthenticatedSessionRepository>(Sessions);
                services.RemoveAll<IUserRepository>();
                services.AddSingleton<IUserRepository>(Users);
                services.RemoveAll<IWebAuthnCredentialRepository>();
                services.AddSingleton<IWebAuthnCredentialRepository>(Passkey);
                services.RemoveAll<IWebAuthnCounterRepository>();
                services.AddSingleton<IWebAuthnCounterRepository>(Passkey);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
                Passkey.Dispose();
        }
    }

    private sealed class UserRepository(params User[] users) : IUserRepository
    {
        private readonly ConcurrentDictionary<Guid, User> _users = new(
            users.Select(user => KeyValuePair.Create(user.Id, user)));

        public ConcurrentQueue<Guid> Reads { get; } = new();
        public int Count => _users.Count;

        public Task AddAsync(User user)
        {
            _users[user.Id] = user;
            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            Reads.Enqueue(id);
            return Task.FromResult(_users.GetValueOrDefault(id));
        }
    }
}

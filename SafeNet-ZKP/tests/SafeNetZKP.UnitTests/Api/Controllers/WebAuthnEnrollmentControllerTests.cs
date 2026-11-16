
using Fido2NetLib;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Internal;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.WebAuthn;
using Xunit;

namespace SafeNetZKP.UnitTests.Api.Controllers;

public class WebAuthnEnrollmentControllerTests
{
    [Fact]
    public async Task Start_WithValidName_ShouldReturn200()
    {
        // Arrange
        using var fixture = new ControllerFixture();

        // Act
        var response = await fixture.Controller.Start(
            new StartEnrollmentRequest
            {
                Name = "  Visitante Teste  "
            });

        // Assert
        var ok = Assert.IsType<OkObjectResult>(response.Result);
        var result = Assert.IsType<StartEnrollmentResult>(ok.Value);

        Assert.Equal(200, ok.StatusCode);
        Assert.Equal("Visitante Teste", result.Name);
        Assert.NotEqual(Guid.Empty, result.UserId);
        Assert.Matches("^[A-F0-9]{64}$", result.EnrollmentToken);

        Assert.Equal(
            result.UserId,
            fixture.Users.SavedUser?.Id);

        Assert.Equal(
            result.UserId,
            fixture.Tickets.TryGetUserId(result.EnrollmentToken));

        Assert.Equal(
            "no-store",
            fixture.Controller.Response.Headers["Cache-Control"].ToString());
    }

    [Fact]
    public async Task Start_WithBlankName_ShouldReturn400()
    {
        // Arrange
        using var fixture = new ControllerFixture();

        // Act
        var response = await fixture.Controller.Start(
            new StartEnrollmentRequest
            {
                Name = "   "
            });

        // Assert
        var error = Assert.IsAssignableFrom<ObjectResult>(
            response.Result);

        Assert.Equal(400, error.StatusCode);
        Assert.IsType<ValidationProblemDetails>(error.Value);
        Assert.Null(fixture.Users.SavedUser);
    }

    [Fact]
    public async Task Start_OutsideDevelopment_ShouldReturn503()
    {
        // Arrange
        using var fixture = new ControllerFixture(
            Environments.Production);

        // Act
        var response = await fixture.Controller.Start(
            new StartEnrollmentRequest
            {
                Name = "Visitante Teste"
            });

        // Assert
        var error = Assert.IsType<ObjectResult>(
            response.Result);

        Assert.Equal(503, error.StatusCode);
        Assert.Null(fixture.Users.SavedUser);
    }

    [Fact]
    public async Task GetOptions_WithValidToken_ShouldReturn200()
    {
        // Arrange
        using var fixture = new ControllerFixture();

        // Primeiro, cria uma conta e obtém o token.
        var startResponse = await fixture.Controller.Start(
            new StartEnrollmentRequest
            {
                Name = "Visitante Teste"
            });

        var startOk = Assert.IsType<OkObjectResult>(
            startResponse.Result);

        var enrollment = Assert.IsType<StartEnrollmentResult>(
            startOk.Value);

        // Act
        var response = await fixture.Controller.GetOptions(
            new EnrollmentOptionsRequest
            {
                EnrollmentToken = enrollment.EnrollmentToken
            },
            CancellationToken.None);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(response.Result);
        var result = Assert.IsType<EnrollmentOptionsResponse>(ok.Value);

        Assert.Equal(200, ok.StatusCode);
        Assert.NotEqual(Guid.Empty, result.OperationId);

        // Verifica o conteúdo das opções WebAuthn.
        var rp = result.Options.GetProperty("rp");

        Assert.Equal(
            "localhost",
            rp.GetProperty("id").GetString());

        var challenge = result.Options
            .GetProperty("challenge")
            .GetString();

        Assert.False(string.IsNullOrWhiteSpace(challenge));

        // Confirma que as opções foram armazenadas.
        var storedOptions = fixture.RegistrationStore.Take(
            result.OperationId,
            enrollment.UserId);

        Assert.NotNull(storedOptions);

        Assert.Equal(
            "no-store",
            fixture.Controller.Response.Headers["Cache-Control"].ToString());
    }

    [Fact]
    public async Task GetOptions_WithInvalidToken_ShouldReturn400()
    {
        // Arrange
        using var fixture = new ControllerFixture();

        // Act
        var response = await fixture.Controller.GetOptions(
            new EnrollmentOptionsRequest
            {
                EnrollmentToken = "token-invalido"
            },
            CancellationToken.None);

        // Assert
        var error = Assert.IsType<BadRequestObjectResult>(
            response.Result);

        Assert.Equal(400, error.StatusCode);
        Assert.IsType<ProblemDetails>(error.Value);
    }

    [Fact]
    public async Task GetOptions_WithExpiredToken_ShouldReturn400()
    {
        // Arrange
        var clock = new TestClock();

        using var fixture = new ControllerFixture(
            Environments.Development,
            clock);

        var startResponse = await fixture.Controller.Start(
            new StartEnrollmentRequest
            {
                Name = "Visitante Teste"
            });

        var startOk = Assert.IsType<OkObjectResult>(
            startResponse.Result);

        var enrollment = Assert.IsType<StartEnrollmentResult>(
            startOk.Value);

        // Avança além dos 10 minutos de validade.
        clock.Advance(TimeSpan.FromMinutes(11));

        // Act
        var response = await fixture.Controller.GetOptions(
            new EnrollmentOptionsRequest
            {
                EnrollmentToken = enrollment.EnrollmentToken
            },
            CancellationToken.None);

        // Assert
        var error = Assert.IsType<BadRequestObjectResult>(
            response.Result);

        Assert.Equal(400, error.StatusCode);
    }

    [Fact]
    public async Task GetOptions_OutsideDevelopment_ShouldReturn503()
    {
        // Arrange
        using var fixture = new ControllerFixture(
            Environments.Production);

        var token = fixture.Tickets.Issue(Guid.NewGuid());

        // Act
        var response = await fixture.Controller.GetOptions(
            new EnrollmentOptionsRequest
            {
                EnrollmentToken = token
            },
            CancellationToken.None);

        // Assert
        var error = Assert.IsType<ObjectResult>(
            response.Result);

        Assert.Equal(503, error.StatusCode);
    }

    // =========================================================
    // CONFIGURAÇÃO COMPARTILHADA DOS TESTES
    // =========================================================

    private sealed class ControllerFixture : IDisposable
    {
        private readonly MemoryCache _cache;
        private readonly ServiceProvider _services;

        public FakeUserRepository Users { get; } = new();

        public WebAuthnEnrollmentTicketStore Tickets { get; }

        public WebAuthnRegistrationStore RegistrationStore { get; }

        public WebAuthnEnrollmentController Controller { get; }

        public ControllerFixture(
            string environmentName = "Development",
            ISystemClock? clock = null)
        {
            // Cache real com relógio opcionalmente simulado.
            var cacheOptions = new MemoryCacheOptions();

            if (clock is not null)
                cacheOptions.Clock = clock;

            _cache = new MemoryCache(cacheOptions);

            Tickets = new WebAuthnEnrollmentTicketStore(_cache);
            RegistrationStore = new WebAuthnRegistrationStore(_cache);

            // Biblioteca Fido2 real.
            IFido2 fido2 = new Fido2NetLib.Fido2(
                new Fido2Configuration
                {
                    RPID = "localhost",
                    RPName = "SafeNet-ZKP",
                    Origins = new HashSet<string>
                    {
                        "http://localhost:4200"
                    },
                    ChallengeSize = 32
                });

            var credentialRepository =
                new FakeCredentialRepository();

            var registrationOptionsService =
                new WebAuthnRegistrationOptionsService(
                    fido2,
                    credentialRepository,
                    RegistrationStore);

            var enrollmentOptionsService =
                new WebAuthnEnrollmentOptionsService(
                    Tickets,
                    Users,
                    registrationOptionsService);

            var startUseCase = new StartEnrollmentUseCase(
                Users,
                Tickets);

            var environment = new FakeEnvironment
            {
                EnvironmentName = environmentName
            };

            // Serviços necessários ao funcionamento do Controller.
            var services = new ServiceCollection();

            services.AddLogging();
            services.AddControllers();

            _services = services.BuildServiceProvider();

            Controller = new WebAuthnEnrollmentController(
                startUseCase,
                environment,
                enrollmentOptionsService)
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext
                    {
                        RequestServices = _services
                    }
                }
            };
        }

        public void Dispose()
        {
            _cache.Dispose();
            _services.Dispose();
        }
    }

    // =========================================================
    // REPOSITÓRIO SIMULADO DE USUÁRIOS
    // =========================================================

    private sealed class FakeUserRepository : IUserRepository
    {
        public User? SavedUser { get; private set; }

        public Task AddAsync(User user)
        {
            SavedUser = user;
            return Task.CompletedTask;
        }

        public Task<User?> GetByIdAsync(Guid id)
        {
            var user = SavedUser?.Id == id
                ? SavedUser
                : null;

            return Task.FromResult(user);
        }
    }

    // =========================================================
    // REPOSITÓRIO SIMULADO DE CREDENCIAIS
    // =========================================================

    private sealed class FakeCredentialRepository
        : IWebAuthnCredentialRepository
    {
        public Task AddAsync(
            WebAuthnCredential credential,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<WebAuthnCredential?> GetByCredentialIdAsync(
            byte[] credentialId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<WebAuthnCredential?>(null);
        }

        public Task<IReadOnlyList<WebAuthnCredential>> GetByUserIdAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<WebAuthnCredential> credentials = [];

            return Task.FromResult(credentials);
        }
    }

    // =========================================================
    // AMBIENTE SIMULADO
    // =========================================================

    private sealed class FakeEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } =
            Environments.Development;

        public string ApplicationName { get; set; } =
            "SafeNetZKP.Api";

        public string ContentRootPath { get; set; } =
            Path.GetTempPath();

        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();

        public string WebRootPath { get; set; } =
            Path.GetTempPath();

        public IFileProvider WebRootFileProvider { get; set; } =
            new NullFileProvider();
    }

    // =========================================================
    // RELÓGIO SIMULADO
    // =========================================================

    private sealed class TestClock : ISystemClock
    {
        public DateTimeOffset UtcNow { get; private set; } =
            new DateTimeOffset(
                2026, 1, 1, 0, 0, 0,
                TimeSpan.Zero);

        public void Advance(TimeSpan duration)
        {
            UtcNow = UtcNow.Add(duration);
        }
    }
}

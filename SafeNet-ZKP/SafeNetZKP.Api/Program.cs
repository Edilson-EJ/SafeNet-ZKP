
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Api.Controllers;
using SafeNetZKP.Api.ExceptionHandlers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Api.Services;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Infrastructure.CaptivePortal;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;
using SafeNetZKP.Infrastructure.Persistence;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Infrastructure.WebAuthn;

var builder = WebApplication.CreateBuilder(args);

// ============================================================
// 1. CONTROLLERS E OPENAPI
// ============================================================

var controllers = builder.Services.AddControllers();
if (!builder.Environment.IsDevelopment())
    controllers.ConfigureApplicationPartManager(manager =>
        manager.FeatureProviders.Add(new DevelopmentControllerFeatureProvider()));
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(SafeNetCookieAuthentication.Configure);
builder.Services.AddAuthorization(options =>
    options.AddPolicy("DevelopmentUserCreation", policy => policy
        .RequireAuthenticatedUser()
        .RequireAssertion(_ => builder.Environment.IsDevelopment())));
builder.Services.AddAntiforgery(SafeNetAntiforgery.Configure);

// ============================================================
// 2. ENTITY FRAMEWORK CORE + POSTGRESQL
// ============================================================

builder.Services.AddDbContext<SafeNetZkpDbContext>(options =>
{
    options.UseNpgsql(
        builder.Configuration.GetConnectionString(
            "DefaultConnection"));
});

// ============================================================
// 3. CONFIGURAÇÃO FIDO2 / WEBAUTHN
// ============================================================

var rpId = builder.Configuration["Fido2:RPID"]
    ?? throw new InvalidOperationException(
        "Fido2:RPID não foi configurado.");

var rpName = builder.Configuration["Fido2:RPName"]
    ?? throw new InvalidOperationException(
        "Fido2:RPName não foi configurado.");

var origins = builder.Configuration
    .GetSection("Fido2:Origins")
    .Get<string[]>();

if (string.IsNullOrWhiteSpace(rpId) ||
    string.IsNullOrWhiteSpace(rpName) ||
    origins is null ||
    origins.Length == 0 ||
    origins.Any(origin => !Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
        uri.Scheme != Uri.UriSchemeHttps))
{
    throw new InvalidOperationException(
        "A configuração FIDO2 está incompleta.");
}

builder.Services.AddScoped<WebAuthnEnrollmentOptionsService>();

builder.Services.AddFido2(options =>
{
    options.RPID = rpId;
    options.RPName = rpName;

    options.Origins = new HashSet<string>(
        origins,
        StringComparer.OrdinalIgnoreCase);
});

// ============================================================
// 4. ARMAZENAMENTO TEMPORÁRIO WEBAUTHN
// ============================================================

// Cache utilizado durante as operações temporárias.
builder.Services.AddMemoryCache();

// Armazena as opções de registro WebAuthn por 5 minutos.
builder.Services.AddSingleton<WebAuthnRegistrationStore>();
builder.Services.AddSingleton<WebAuthnAuthenticationStore>();

// Armazena os tokens de inscrição inicial por 10 minutos.
builder.Services.AddSingleton<WebAuthnEnrollmentTicketStore>();

// Disponibiliza o mesmo armazenamento pela interface.
builder.Services.AddSingleton<IEnrollmentTicketIssuer>(
    provider =>
        provider.GetRequiredService<WebAuthnEnrollmentTicketStore>());

// ============================================================
// 5. CONTEXTO DO USUÁRIO AUTENTICADO
// ============================================================

builder.Services.AddHttpContextAccessor();

builder.Services.AddScoped<
    ICurrentUserContext,
    HttpCurrentUserContext>();

// ============================================================
// 6. INJEÇÃO DE DEPENDÊNCIA - REPOSITÓRIOS
// ============================================================

builder.Services.AddScoped<
    IUserRepository,
    PostgresUserRepository>();

builder.Services.AddScoped<
    IWebAuthnCredentialRepository,
    PostgresWebAuthnCredentialRepository>();
builder.Services.AddScoped<IWebAuthnCounterRepository, PostgresWebAuthnCredentialRepository>();
builder.Services.AddScoped<IAuthenticatedSessionRepository, PostgresAuthenticatedSessionRepository>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<AuthenticatedSessionService>();
builder.Services.AddScoped<INetworkAccessRepository, PostgresNetworkAccessRepository>();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<CaptivePortalIngress>();
    builder.Services.AddSingleton<InMemoryCaptivePortalGateway>();
    builder.Services.AddSingleton<ICaptivePortalGateway>(provider =>
        provider.GetRequiredService<InMemoryCaptivePortalGateway>());
    builder.Services.AddSingleton<ICaptivePortalAssociationGateway>(provider =>
        provider.GetRequiredService<InMemoryCaptivePortalGateway>());
    builder.Services.AddScoped<NetworkAccessService>();
    builder.Services.AddScoped<PersistentNetworkAccessService>();
    builder.Services.AddScoped<NetworkRevocationProcessor>();

    if (builder.Configuration.GetValue<bool>("CaptivePortal:ProcessRevocations"))
        builder.Services.AddHostedService<NetworkRevocationWorker>();
}

// ============================================================
// 7. INJEÇÃO DE DEPENDÊNCIA - CASOS DE USO
// ============================================================

// Usuários
builder.Services.AddScoped<CreateUserUseCase>();
builder.Services.AddScoped<GetUserByIdUseCase>();

// Inscrição inicial WebAuthn
builder.Services.AddScoped<StartEnrollmentUseCase>();

// Geração das opções de registro WebAuthn
builder.Services.AddScoped<WebAuthnRegistrationOptionsService>();
builder.Services.AddScoped<WebAuthnRegistrationCompletionService>();
builder.Services.AddScoped<WebAuthnAuthenticationOptionsService>();
builder.Services.AddScoped<WebAuthnAuthenticationCompletionService>();

// ============================================================
// 8. TRATAMENTO GLOBAL DE EXCEÇÕES
// ============================================================

builder.Services.AddProblemDetails();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

// ============================================================
// 9. RATE LIMITING - INSCRIÇÃO WEBAUTHN
// ============================================================

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode =
        StatusCodes.Status429TooManyRequests;

    options.AddPolicy("captive-portal", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            (context.Connection.RemoteIpAddress, Write: HttpMethods.IsPost(context.Request.Method)),
            partition => new FixedWindowRateLimiterOptions
            {
                PermitLimit = partition.Write ? 12 : 60,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));

    options.AddPolicy("authentication-options", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));

    options.AddPolicy(
        "enrollment-start",
        context => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey:
                context.Connection.RemoteIpAddress?.ToString()
                ?? "unknown",

            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
});

// ============================================================
// 10. BUILD DA APLICAÇÃO
// ============================================================

var app = builder.Build();

// ============================================================
// 11. PIPELINE HTTP
// ============================================================

// Tratamento global de exceções.
app.UseExceptionHandler();

// Swagger / OpenAPI somente em desenvolvimento.
if (app.Environment.IsDevelopment())
{
    // Página local para validação manual WebAuthn; não é servida em produção.
    app.UseStaticFiles();
    app.MapOpenApi();

    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint(
            "/openapi/v1.json",
            "SafeNet-ZKP API v1");
    });
}

// Evita o aviso de porta HTTPS nos testes locais.
// Fora de Development, exige configuração HTTPS adequada.
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// Bloqueia HTTP antes de processar cookies, desafios ou tokens de inscrição.
app.Use(async (context, next) =>
{
    if (!context.Request.IsHttps &&
        context.Request.Path.StartsWithSegments("/api") &&
        context.Request.Path != "/api/health" &&
        context.Request.Path != "/api/health/")
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return;
    }

    await next(context);
});

// Identifica a rota da requisição.
app.UseRouting();

// Aplica as políticas de limitação de requisições.
app.UseRateLimiter();

// Autentica antes de aplicar as políticas de autorização.
app.UseAuthentication();
app.UseAuthorization();

// Mapeia os Controllers.
app.MapControllers().RequireAuthorization();

// Inicia a aplicação.
app.Run();

public partial class Program;


using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Api.ExceptionHandlers;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Interfaces.Security;
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

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(SafeNetCookieAuthentication.Configure);
builder.Services.AddAuthorization();
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
    origins.Any(string.IsNullOrWhiteSpace))
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

// Identifica a rota da requisição.
app.UseRouting();

// Aplica as políticas de limitação de requisições.
app.UseRateLimiter();

// Autentica antes de aplicar as políticas de autorização.
app.UseAuthentication();
app.UseAuthorization();

// Mapeia os Controllers.
app.MapControllers();

// Inicia a aplicação.
app.Run();

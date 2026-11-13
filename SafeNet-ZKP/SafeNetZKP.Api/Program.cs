using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using SafeNetZKP.Infrastructure.Persistence;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Api.ExceptionHandlers;
using SafeNetZKP.Infrastructure.WebAuthn;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;

var builder = WebApplication.CreateBuilder(args);

// Controllers
builder.Services.AddControllers();

// Entity Framework Core + PostgreSQL
builder.Services.AddDbContext<SafeNetZkpDbContext>(options =>
{
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("DefaultConnection"));
});

// OpenAPI
builder.Services.AddOpenApi();

// Armazenamento temporário do registro WebAuthn
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<WebAuthnRegistrationStore>();

// Contexto do usuário autenticado
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();

 // Configuração FIDO2/WebAuthn
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

builder.Services.AddFido2(options =>
{
    options.RPID = rpId;
    options.RPName = rpName;

    options.Origins = new HashSet<string>(
        origins,
        StringComparer.OrdinalIgnoreCase);
});



 // Dependency Injection - Casos de uso
builder.Services.AddScoped<CreateUserUseCase>();
builder.Services.AddScoped<GetUserByIdUseCase>();

// Dependency Injection - Repositórios
builder.Services.AddScoped<IUserRepository, PostgresUserRepository>();
builder.Services.AddScoped<
    IWebAuthnCredentialRepository,
    PostgresWebAuthnCredentialRepository>();

// Tratamento global de exceções
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();


builder.Services.AddSingleton<IEnrollmentTicketIssuer>(
    provider => provider.GetRequiredService<WebAuthnEnrollmentTicketStore>());

builder.Services.AddScoped<StartEnrollmentUseCase>();

var app = builder.Build();

// Exception Handler deve estar antes dos endpoints
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();

    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint(
            "/openapi/v1.json",
            "SafeNet-ZKP API v1");
    });
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
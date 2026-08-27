using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using SafeNetZKP.Infrastructure.Persistence;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Api.ExceptionHandlers;

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

// Dependency Injection
builder.Services.AddScoped<CreateUserUseCase>();
builder.Services.AddScoped<GetUserByIdUseCase>();
builder.Services.AddScoped<IUserRepository, PostgresUserRepository>();

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

// Tratamento de erros
builder.Services.AddProblemDetails();

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
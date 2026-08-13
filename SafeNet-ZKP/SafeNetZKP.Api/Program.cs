using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Application.UseCases.Users.GetUserById;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddOpenApi();

builder.Services.AddScoped<CreateUserUseCase>();

builder.Services.AddScoped<GetUserByIdUseCase>();

builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();

var app = builder.Build();

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
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Infrastructure.Repositories;
using SafeNetZKP.Application.UseCases.Users.GetUserById;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddDbContext<SafeNetZkpDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
}
);

builder.Services.AddOpenApi();

builder.Services.AddScoped<CreateUserUseCase>();

builder.Services.AddScoped<GetUserByIdUseCase>();

builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();

var app = builder.Build();

//Remove depois
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider
        .GetRequiredService<SafeNetZkpDbContext>();

    var canConnect = await dbContext.Database.CanConnectAsync();

    Console.WriteLine(
        $"Conexão com PostgreSQL: {canConnect}");
}

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
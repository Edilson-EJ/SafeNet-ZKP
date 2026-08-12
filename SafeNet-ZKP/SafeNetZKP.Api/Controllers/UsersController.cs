using Microsoft.AspNetCore.Mvc;
using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.UseCases.Users.CreateUser;


namespace SafeNetZKP.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly CreateUserUseCase _createUserUseCase;
    public UsersController(CreateUserUseCase createUserUseCase)
    {
        _createUserUseCase = createUserUseCase;
    }
    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        var response = _createUserUseCase.Execute(request);

        return Created($"/api/users/{response.Id}", response);
    }
}
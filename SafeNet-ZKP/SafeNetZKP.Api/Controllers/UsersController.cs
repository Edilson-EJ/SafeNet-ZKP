using Microsoft.AspNetCore.Mvc;
using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.UseCases.Users.GetUserById;

namespace SafeNetZKP.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly CreateUserUseCase _createUserUseCase;

    private readonly GetUserByIdUseCase _getUserByIdUseCase;
    public UsersController(
    CreateUserUseCase createUserUseCase,
    GetUserByIdUseCase getUserByIdUseCase)
    {
        _createUserUseCase = createUserUseCase;
        _getUserByIdUseCase = getUserByIdUseCase;
    }
    [HttpPost]
    public async Task<IActionResult> Create(CreateUserRequest request)
    {
        var response = await _createUserUseCase.ExecuteAsync(request);

        return Created($"/api/users/{response.Id}", response);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var response = await _getUserByIdUseCase.ExecuteAsync(id);

        if (response is null)
            return NotFound();

        return Ok(response);
    }
}
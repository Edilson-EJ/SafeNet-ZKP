
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
    [ProducesResponseType(typeof(CreateUserResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Create(CreateUserRequest request)
    {
        var response = await _createUserUseCase.ExecuteAsync(request);

        return Created($"/api/users/{response.Id}", response);
    }

    
    
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(CreateUserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetById(Guid id)
    {
        var response = await _getUserByIdUseCase.ExecuteAsync(id);

        if (response is null)
        {
            return Problem(
                statusCode: StatusCodes.Status404NotFound,
                title: "Usuário não encontrado.",
                detail: "Não foi encontrado um usuário com o identificador informado.");
        }

        return Ok(response);
    }


}

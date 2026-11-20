using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.UseCases.Users.CreateUser;
using SafeNetZKP.Application.UseCases.Users.GetUserById;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Authorize]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly CreateUserUseCase _createUserUseCase;
    private readonly GetUserByIdUseCase _getUserByIdUseCase;
    private readonly ICurrentUserContext _currentUser;
    private readonly IAntiforgery _antiforgery;

    public UsersController(
        CreateUserUseCase createUserUseCase,
        GetUserByIdUseCase getUserByIdUseCase,
        ICurrentUserContext currentUser,
        IAntiforgery antiforgery)
    {
        _createUserUseCase = createUserUseCase;
        _getUserByIdUseCase = getUserByIdUseCase;
        _currentUser = currentUser;
        _antiforgery = antiforgery;
    }

    [HttpPost]
    [Authorize(Policy = "DevelopmentUserCreation")]
    [ProducesResponseType(typeof(CreateUserResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Create(CreateUserRequest request)
    {
        if (!Request.IsHttps || _currentUser.UserId is null)
            return Forbid();

        try
        {
            await _antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return BadRequest();
        }

        var response = await _createUserUseCase.ExecuteAsync(request);

        return Created($"/api/users/{response.Id}", response);
    }

    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(CreateUserResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetById(Guid id)
    {
        var currentUserId = _currentUser.UserId;
        if (currentUserId is null)
            return Forbid();

        if (currentUserId != id)
            return UserNotFound();

        var response = await _getUserByIdUseCase.ExecuteAsync(currentUserId.Value);
        return response is null ? UserNotFound() : Ok(response);
    }

    private ObjectResult UserNotFound() => Problem(
        statusCode: StatusCodes.Status404NotFound,
        title: "Usuário não encontrado.",
        detail: "Não foi encontrado um usuário com o identificador informado.");
}

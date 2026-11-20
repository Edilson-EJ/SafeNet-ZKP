using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.Users.GetUserById;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/auth")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class AuthController(
    ICurrentUserContext currentUser,
    GetUserByIdUseCase getUserById,
    IAntiforgery antiforgery,
    AuthenticatedSessionService sessions) : ControllerBase
{
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        Response.Headers.CacheControl = "no-store";
        var userId = currentUser.UserId;
        if (userId is null)
            return Unauthorized();
        var user = await getUserById.ExecuteAsync(userId.Value);
        return user is null ? Unauthorized() : Ok(new SessionUserResponse(user.Id, user.Name));
    }

    [HttpGet("csrf")]
    public IActionResult Csrf()
    {
        Response.Headers.CacheControl = "no-store";
        if (!Request.IsHttps)
            return StatusCode(StatusCodes.Status403Forbidden);
        if (currentUser.UserId is null)
            return Unauthorized();
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new CsrfTokenResponse(tokens.RequestToken!));
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        Response.Headers.CacheControl = "no-store";
        if (!Request.IsHttps)
            return StatusCode(StatusCodes.Status403Forbidden);
        if (currentUser.UserId is not { } userId)
            return Unauthorized();
        try
        {
            await antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return BadRequest();
        }

        const string scheme = CookieAuthenticationDefaults.AuthenticationScheme;
        var authentication = await HttpContext.AuthenticateAsync(scheme);
        var sessionId = authentication.Properties is { } properties
            ? SafeNetCookieAuthentication.GetSessionId(properties) : null;
        if (!authentication.Succeeded || sessionId is null)
            return Unauthorized();

        await sessions.RevokeAsync(sessionId, userId, HttpContext.RequestAborted);
        await HttpContext.SignOutAsync(scheme);
        return NoContent();
    }
}

public sealed record SessionUserResponse(Guid UserId, string Name);
public sealed record CsrfTokenResponse(string Token);

using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeNetZKP.Infrastructure.WebAuthn;
using SafeNetZKP.Api.Security;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Route("api/webauthn/authentication")]
public sealed class WebAuthnAuthenticationController(
    IWebHostEnvironment environment,
    WebAuthnAuthenticationOptionsService optionsService,
    WebAuthnAuthenticationCompletionService completionService,
    IConfiguration configuration) : ControllerBase
{
    [HttpPost("options")]
    [AllowAnonymous]
    [EnableRateLimiting("authentication-options")]
    public IActionResult GetOptions()
    {
        Response.Headers.CacheControl = "no-store";
        if (!environment.IsDevelopment())
            return StatusCode(StatusCodes.Status503ServiceUnavailable);

        var (operationId, options) = optionsService.Generate();
        using var json = JsonDocument.Parse(options.ToJson());
        return Ok(new AuthenticationOptionsResponse(operationId, json.RootElement.Clone()));
    }

    [HttpPost("complete")]
    [AllowAnonymous]
    [EnableRateLimiting("authentication-options")]
    [RequestSizeLimit(65536)]
    public async Task<IActionResult> Complete([FromBody] AuthenticationCompletionRequest request,
        CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!environment.IsDevelopment())
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        if (!IsAllowedSameOriginRequest())
            return StatusCode(StatusCodes.Status403Forbidden);
        if (request.Response is null)
            return BadRequest();
        var userId = await completionService.CompleteAsync(request.OperationId, request.Response, cancellationToken);
        if (userId is null || userId == Guid.Empty)
            return BadRequest();

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            SafeNetCookieAuthentication.CreatePrincipal(userId.Value),
            new AuthenticationProperties { IsPersistent = false, AllowRefresh = false });
        return Ok(new AuthenticationCompletionResponse(userId.Value));
    }

    private bool IsAllowedSameOriginRequest()
    {
        if (!Request.IsHttps || Request.Headers.Origin.Count != 1 || !Request.Host.HasValue)
            return false;

        var origin = Request.Headers.Origin.ToString();
        var requestOrigin = $"https://{Request.Host.Value}";
        var allowedOrigins = configuration.GetSection("Fido2:Origins").Get<string[]>() ?? [];
        return string.Equals(origin, requestOrigin, StringComparison.OrdinalIgnoreCase) &&
            allowedOrigins.Any(allowed => string.Equals(allowed, origin, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed record AuthenticationOptionsResponse(string OperationId, JsonElement Options);

public sealed class AuthenticationCompletionRequest
{
    [Required, RegularExpression("^[0-9a-fA-F]{64}$")]
    public string OperationId { get; init; } = string.Empty;
    [Required]
    public AuthenticatorAssertionRawResponse? Response { get; init; }
}

public sealed record AuthenticationCompletionResponse(Guid UserId);

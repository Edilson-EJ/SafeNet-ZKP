using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeNetZKP.Infrastructure.WebAuthn;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Route("api/webauthn/authentication")]
public sealed class WebAuthnAuthenticationController(
    IWebHostEnvironment environment,
    WebAuthnAuthenticationOptionsService optionsService,
    WebAuthnAuthenticationCompletionService completionService) : ControllerBase
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
        if (request.Response is null)
            return BadRequest();
        var userId = await completionService.CompleteAsync(request.OperationId, request.Response, cancellationToken);
        return userId is null ? BadRequest() : Ok(new AuthenticationCompletionResponse(userId.Value));
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

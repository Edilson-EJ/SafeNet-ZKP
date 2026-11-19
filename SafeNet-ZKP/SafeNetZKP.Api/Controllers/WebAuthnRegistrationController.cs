using System.ComponentModel.DataAnnotations;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeNetZKP.Infrastructure.WebAuthn;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Route("api/webauthn/enrollment")]
public sealed class WebAuthnRegistrationController(
    IWebHostEnvironment environment,
    WebAuthnRegistrationCompletionService completion) : ControllerBase
{
    [HttpPost("complete")]
    [AllowAnonymous]
    [EnableRateLimiting("enrollment-start")]
    [RequestSizeLimit(65536)]
    public async Task<IActionResult> Complete(
        [FromBody] CompleteRegistrationRequest request, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        if (!environment.IsDevelopment())
            return StatusCode(StatusCodes.Status503ServiceUnavailable);

        if (request.OperationId == Guid.Empty || request.Response is null ||
            !await completion.CompleteAsync(request.OperationId, request.EnrollmentToken,
                request.Response, cancellationToken))
            return BadRequest(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Não foi possível concluir a inscrição."
            });

        return NoContent();
    }
}

public sealed class CompleteRegistrationRequest
{
    [Required]
    public Guid OperationId { get; init; }

    [Required]
    [RegularExpression("^[0-9a-fA-F]{64}$")]
    public string EnrollmentToken { get; init; } = string.Empty;

    [Required]
    public AuthenticatorAttestationRawResponse? Response { get; init; }
}

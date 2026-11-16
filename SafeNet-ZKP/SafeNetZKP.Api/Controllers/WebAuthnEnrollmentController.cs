
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;
using SafeNetZKP.Infrastructure.WebAuthn;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Route("api/webauthn/enrollment")]
public sealed class WebAuthnEnrollmentController : ControllerBase
{
    private readonly StartEnrollmentUseCase _startEnrollmentUseCase;
    private readonly WebAuthnEnrollmentOptionsService _optionsService;
    private readonly IWebHostEnvironment _environment;

    public WebAuthnEnrollmentController(
        StartEnrollmentUseCase startEnrollmentUseCase,
        IWebHostEnvironment environment,
        WebAuthnEnrollmentOptionsService optionsService)
    {
        _startEnrollmentUseCase = startEnrollmentUseCase;
        _environment = environment;
        _optionsService = optionsService;
    }

    // =========================================================
    // 1. INICIAR INSCRIÇÃO
    // POST /api/webauthn/enrollment/start
    // =========================================================

    [HttpPost("start")]
    [AllowAnonymous]
    [EnableRateLimiting("enrollment-start")]
    [ProducesResponseType(
        typeof(StartEnrollmentResult),
        StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<StartEnrollmentResult>> Start(
        [FromBody] StartEnrollmentRequest request)
    {
        if (!_environment.IsDevelopment())
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new ProblemDetails
                {
                    Status = StatusCodes.Status503ServiceUnavailable,
                    Title = "Inscrição inicial indisponível neste ambiente."
                });
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            ModelState.AddModelError(
                nameof(request.Name),
                "O nome do usuário é obrigatório.");

            return ValidationProblem(ModelState);
        }

        var result = await _startEnrollmentUseCase.ExecuteAsync(
            request.Name.Trim());

        Response.Headers["Cache-Control"] = "no-store";

        return Ok(result);
    }

    // =========================================================
    // 2. GERAR OPÇÕES WEBAUTHN
    // POST /api/webauthn/enrollment/options
    // =========================================================

    [HttpPost("options")]
    [AllowAnonymous]
    [EnableRateLimiting("enrollment-start")]
    [ProducesResponseType(
        typeof(EnrollmentOptionsResponse),
        StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<EnrollmentOptionsResponse>> GetOptions(
        [FromBody] EnrollmentOptionsRequest request,
        CancellationToken cancellationToken)
    {
        if (!_environment.IsDevelopment())
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new ProblemDetails
                {
                    Status = StatusCodes.Status503ServiceUnavailable,
                    Title = "Inscrição indisponível neste ambiente."
                });
        }

        // Identifica o usuário pelo token e gera as opções.
        var result = await _optionsService.GenerateAsync(
            request.EnrollmentToken,
            cancellationToken);

        if (result is null)
        {
            return BadRequest(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Token de inscrição inválido ou expirado."
            });
        }

        // Preserva o formato JSON gerado pela biblioteca Fido2.
        using var json = JsonDocument.Parse(
            result.Options.ToJson());

        var response = new EnrollmentOptionsResponse(
            result.OperationId,
            json.RootElement.Clone());

        Response.Headers["Cache-Control"] = "no-store";

        return Ok(response);
    }
}

// ============================================================
// DTO - INICIAR INSCRIÇÃO
// ============================================================

public sealed class StartEnrollmentRequest
{
    [Required]
    [StringLength(100, MinimumLength = 1)]
    public string Name { get; init; } = string.Empty;
}

// ============================================================
// DTO - SOLICITAR OPÇÕES WEBAUTHN
// ============================================================

public sealed class EnrollmentOptionsRequest
{
    [Required]
    [RegularExpression("^[0-9a-fA-F]{64}$")]
    public string EnrollmentToken { get; init; } = string.Empty;
}

// ============================================================
// DTO - RESPOSTA COM OPÇÕES WEBAUTHN
// ============================================================

public sealed record EnrollmentOptionsResponse(
    Guid OperationId,
    JsonElement Options);

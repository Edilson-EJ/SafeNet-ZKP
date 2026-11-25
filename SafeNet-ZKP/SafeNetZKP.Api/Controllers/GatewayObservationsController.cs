using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Application.Interfaces.Repositories;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[AllowAnonymous] // The gateway authenticates the message independently of browser cookies.
[EnableRateLimiting("gateway-observations")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[Route("api/captive-portal/gateway/observations")]
public sealed class GatewayObservationsController(GatewayObservationAuthentication authentication,
    IGatewayObservationRepository observations) : ControllerBase
{
    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 4
    };

    [HttpPost]
    [Consumes("application/json")]
    [RequestSizeLimit(GatewayObservationAuthentication.MaxBodyBytes + 1)]
    public async Task<IActionResult> Record(CancellationToken ct)
    {
        if (!Request.IsHttps)
            return StatusCode(StatusCodes.Status403Forbidden);
        if (Request.QueryString.HasValue || Request.Headers.ContainsKey("Content-Encoding"))
            return BadRequest();

        var body = new byte[GatewayObservationAuthentication.MaxBodyBytes + 1];
        var length = await Request.Body.ReadAtLeastAsync(body, body.Length, false, ct);
        if (length == body.Length)
            return StatusCode(StatusCodes.Status413PayloadTooLarge);
        if (!authentication.TryAuthenticate(Request.Headers, body.AsSpan(0, length), out var sender))
            return Unauthorized();

        Payload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<Payload>(body.AsSpan(0, length), PayloadOptions);
        }
        catch (JsonException)
        {
            return BadRequest();
        }
        if (payload is null || payload.ConnectionId == Guid.Empty || payload.Generation <= 0)
            return BadRequest();
        if (payload.GatewayId != sender.GatewayId)
            return StatusCode(StatusCodes.Status403Forbidden);

        try
        {
            var accepted = await observations.TryRecordAsync(new(sender.GatewayId, sender.Nonce,
                payload.ConnectionId, payload.Generation, sender.ObservedAt, sender.ExpiresAt), ct);
            return accepted ? NoContent() : Conflict();
        }
        catch (DbException) when (!ct.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private sealed record Payload(Guid GatewayId, Guid ConnectionId, long Generation);
}

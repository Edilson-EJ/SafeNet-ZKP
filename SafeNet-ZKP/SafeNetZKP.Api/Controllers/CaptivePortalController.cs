using System.ComponentModel.DataAnnotations;
using System.Data.Common;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Api.Security;
using SafeNetZKP.Api.Services;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Application.Services;
using SafeNetZKP.Application.UseCases.CaptivePortal;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Api.Controllers;

[ApiController]
[Authorize]
[EnableRateLimiting("captive-portal")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[Route("api/captive-portal")]
public sealed class CaptivePortalController(
    ICurrentUserContext currentUser,
    AuthenticatedSessionService sessions,
    IAntiforgery antiforgery,
    CaptivePortalIngress ingress,
    PersistentNetworkAccessService access) : ControllerBase
{
    [HttpPost("associations")]
    [RequestSizeLimit(4096)]
    public Task<IActionResult> Associate(AssociateConnectionRequest request, CancellationToken ct) =>
        ExecuteAsync(async (caller, sessionId) =>
        {
            var observation = ingress.FindObservation(sessionId, request.Reference);
            if (observation is null)
                return NotFound();

            var binding = await access.AssociateAsync(caller, observation, request.Reference, ct);
            if (binding is null)
                return NotFound();

            ingress.CompleteAssociation(sessionId, request.Reference, binding);
            return StatusCode(StatusCodes.Status201Created, new NetworkAssociationResponse(binding.Id));
        }, ct);

    [HttpPost("operations")]
    [RequestSizeLimit(4096)]
    public Task<IActionResult> AuthorizeAccess(AuthorizeNetworkRequest request, CancellationToken ct) =>
        ExecuteAsync(async (caller, sessionId) =>
        {
            if (request.AssociationId == Guid.Empty || request.IdempotencyKey == Guid.Empty)
                return BadRequest();

            var binding = ingress.FindBinding(sessionId, request.AssociationId);
            if (binding is null)
                return NotFound();

            var result = await access.AuthorizeAsync(caller, binding, request.IdempotencyKey,
                TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), ct);
            return result is null ? Conflict() : MutationResult(result);
        }, ct);

    [HttpGet("operations/{operationId:guid}")]
    public Task<IActionResult> GetOperation(Guid operationId, CancellationToken ct) =>
        ExecuteAsync(async (caller, _) =>
        {
            var result = await access.GetOperationAsync(caller, operationId, ct);
            return result is null ? NotFound() : Ok(ToResponse(result));
        }, ct);

    [HttpGet("grants")]
    public Task<IActionResult> ListGrants(CancellationToken ct) =>
        ExecuteAsync(async (caller, _) =>
        {
            var results = await access.ListGrantsAsync(caller, ct);
            return results is null ? Unauthorized() : Ok(results.Select(result =>
                new NetworkGrantResponse(result.OperationId, StateName(result.LastKnownState), result.AccessUntil)));
        }, ct);

    [HttpPost("operations/{operationId:guid}/revocation")]
    [RequestSizeLimit(4096)]
    public Task<IActionResult> Revoke(Guid operationId, CancellationToken ct) =>
        ExecuteAsync(async (caller, _) =>
        {
            var result = await access.RequestRevocationAsync(caller, operationId, ct);
            return result is null ? NotFound() : MutationResult(result);
        }, ct);

    private async Task<IActionResult> ExecuteAsync(Func<NetworkAccessCaller, string, Task<IActionResult>> action,
        CancellationToken ct)
    {
        var authentication = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authentication.Succeeded || authentication.Properties is not { } properties ||
            SafeNetCookieAuthentication.GetSessionId(properties) is not { } sessionId ||
            currentUser.UserId is not { } userId)
            return Unauthorized();

        if (HttpMethods.IsPost(Request.Method))
        {
            try
            {
                await antiforgery.ValidateRequestAsync(HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                return BadRequest();
            }
        }

        try
        {
            var result = await action(new NetworkAccessCaller(currentUser, sessionId), sessionId);
            if (!await sessions.IsActiveAsync(sessionId, userId, ct))
                return Unauthorized();
            if (result is ObjectResult { Value: NetworkOperationResponse operation })
                HttpContext.Items[SecurityOutcomeLogging.NetworkState] = operation.State;
            return result;
        }
        catch (Exception exception) when (!ct.IsCancellationRequested &&
            (exception is DbException or GatewayCommunicationException or TimeoutException ||
             exception is DbUpdateException { InnerException: DbException }))
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private IActionResult MutationResult(GatewayOperationResult result) => result.State switch
    {
        NetworkAccessState.Pending or NetworkAccessState.Indeterminate =>
            AcceptedAtAction(nameof(GetOperation), new { operationId = result.OperationId }, ToResponse(result)),
        NetworkAccessState.Denied => StatusCode(StatusCodes.Status403Forbidden, ToResponse(result)),
        _ => Ok(ToResponse(result))
    };

    private static NetworkOperationResponse ToResponse(GatewayOperationResult result) =>
        new(result.OperationId, StateName(result.State),
            result.State == NetworkAccessState.Authorized ? result.Grant?.ExpiresAt : null);

    private static string StateName(NetworkAccessState state) => state.ToString().ToLowerInvariant();
}

public sealed record AssociateConnectionRequest(
    [Required, RegularExpression("^[0-9a-fA-F]{64}$")] string Reference);

public sealed record AuthorizeNetworkRequest(Guid AssociationId, Guid IdempotencyKey);
public sealed record NetworkAssociationResponse(Guid AssociationId);
public sealed record NetworkOperationResponse(Guid OperationId, string State, DateTimeOffset? ExpiresAt);
public sealed record NetworkGrantResponse(Guid OperationId, string LastKnownState, DateTimeOffset AccessUntil);

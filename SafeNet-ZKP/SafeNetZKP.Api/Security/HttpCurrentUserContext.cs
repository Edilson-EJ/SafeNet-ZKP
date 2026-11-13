
using System.Security.Claims;
using SafeNetZKP.Application.Interfaces.Security;

namespace SafeNetZKP.Api.Security;

public sealed class HttpCurrentUserContext : ICurrentUserContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpCurrentUserContext(
        IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid? UserId
    {
        get
        {
            var principal = _httpContextAccessor.HttpContext?.User;

            if (principal?.Identity?.IsAuthenticated != true)
                return null;

            var userIdValue =
                principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? principal.FindFirst("sub")?.Value;

            if (!Guid.TryParse(userIdValue, out var userId))
                return null;

            return userId == Guid.Empty ? null : userId;
        }
    }
}

using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.UseCases.CaptivePortal;

// A composição deve extrair estes dados do principal e do ticket já autenticados.
public sealed class NetworkAccessCaller(ICurrentUserContext user, string? sessionIdentifier)
{
    internal ICurrentUserContext User { get; } = user;
    internal string? SessionIdentifier { get; } = sessionIdentifier;
}

public sealed class NetworkAccessBinding
{
    internal NetworkAccessBinding(NetworkAssociation association) => Association = association;
    internal NetworkAssociation Association { get; }
}

public abstract class NetworkAccessOperation
{
    internal NetworkAccessOperation(NetworkAssociation association, Guid id, Guid grantId)
    {
        Association = association;
        Id = id;
        GrantId = grantId;
    }

    public Guid Id { get; }
    internal Guid GrantId { get; }
    internal NetworkAssociation Association { get; }
}

public sealed class NetworkAccessAuthorization : NetworkAccessOperation
{
    internal NetworkAccessAuthorization(NetworkAuthorizationRequest request)
        : base(request.Association, request.OperationId, request.GrantId) => Request = request;

    internal NetworkAuthorizationRequest Request { get; }
}

public sealed class NetworkAccessRevocation : NetworkAccessOperation
{
    internal NetworkAccessRevocation(NetworkAssociation association, NetworkRevocationRequest request)
        : base(association, request.OperationId, request.GrantId) => Request = request;

    internal NetworkRevocationRequest Request { get; }
}

using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.Interfaces.Gateways;

public interface ICaptivePortalAssociationGateway
{
    Task<NetworkAssociation?> AssociateAsync(ObservedNetworkConnection observation,
        NetworkAssociationRequest request, CancellationToken cancellationToken);
}

// Falha de transporte sem confirmação de que o gateway rejeitou ou aplicou a operação.
public sealed class GatewayCommunicationException : Exception;

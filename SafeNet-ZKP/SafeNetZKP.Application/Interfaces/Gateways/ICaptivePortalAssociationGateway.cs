using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.Interfaces.Gateways;

public interface ICaptivePortalAssociationGateway
{
    // Atomically consumes a reference for the observation's current generation and pre-bound session.
    Task<NetworkAssociation?> AssociateAsync(ObservedNetworkConnection observation,
        NetworkAssociationRequest request, CancellationToken cancellationToken);
}

// Falha de transporte sem confirmação de que o gateway rejeitou ou aplicou a operação.
public sealed class GatewayCommunicationException : Exception;

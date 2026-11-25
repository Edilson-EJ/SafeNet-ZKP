using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Application.Interfaces.Repositories;

public interface IGatewayObservationRepository
{
    // Records the observation and consumes the gateway nonce atomically.
    // False means the nonce has already been consumed.
    Task<bool> TryRecordAsync(GatewayObservation observation, CancellationToken ct);
}

namespace SafeNetZKP.Application.Interfaces.Repositories;

public interface IWebAuthnCounterRepository
{
    Task<bool> TryUpdateCounterAsync(Guid credentialId, uint expectedCounter, uint newCounter,
        CancellationToken cancellationToken = default);
}

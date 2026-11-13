
using Fido2NetLib;
using Fido2NetLib.Objects;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed class WebAuthnRegistrationOptionsService
{
    private readonly IFido2 _fido2;

    private readonly IWebAuthnCredentialRepository
        _credentialRepository;

    private readonly WebAuthnRegistrationStore
        _registrationStore;

    public WebAuthnRegistrationOptionsService(
        IFido2 fido2,
        IWebAuthnCredentialRepository credentialRepository,
        WebAuthnRegistrationStore registrationStore)
    {
        _fido2 = fido2;
        _credentialRepository = credentialRepository;
        _registrationStore = registrationStore;
    }

    public async Task<(Guid OperationId, CredentialCreateOptions Options)>
        GenerateAsync(
            User user,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        // 1. Consultar credenciais existentes do usuário.
        var credentials =
            await _credentialRepository.GetByUserIdAsync(
                user.Id,
                cancellationToken);

        // 2. Preparar os identificadores das credenciais existentes.
        var excludedCredentials = credentials
            .Select(c => new PublicKeyCredentialDescriptor(
                c.CredentialId))
            .ToList();

        // 3. Representar o usuário para o protocolo WebAuthn.
        var fido2User = new Fido2User
        {
            Id = user.Id.ToByteArray(),
            Name = user.Name,
            DisplayName = user.Name
        };

        // 4. Gerar as opções de registro WebAuthn.
        var options = _fido2.RequestNewCredential(
            new RequestNewCredentialParams
            {
                User = fido2User,
                ExcludeCredentials = excludedCredentials,
                AuthenticatorSelection =
                    AuthenticatorSelection.Default,
                AttestationPreference =
                    AttestationConveyancePreference.None
            });

        // 5. Armazenar temporariamente as opções.
        var operationId = _registrationStore.Store(
            user.Id,
            options);

        // 6. Retornar o identificador e as opções.
        return (operationId, options);
    }
}

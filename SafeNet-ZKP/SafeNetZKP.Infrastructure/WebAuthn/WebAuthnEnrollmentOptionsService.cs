
using Fido2NetLib;
using SafeNetZKP.Application.Interfaces.Repositories;

namespace SafeNetZKP.Infrastructure.WebAuthn;

public sealed record WebAuthnEnrollmentOptionsResult(
    Guid OperationId,
    CredentialCreateOptions Options);

public sealed class WebAuthnEnrollmentOptionsService
{
    private readonly WebAuthnEnrollmentTicketStore _ticketStore;
    private readonly IUserRepository _userRepository;
    private readonly WebAuthnRegistrationOptionsService _optionsService;

    public WebAuthnEnrollmentOptionsService(
        WebAuthnEnrollmentTicketStore ticketStore,
        IUserRepository userRepository,
        WebAuthnRegistrationOptionsService optionsService)
    {
        _ticketStore = ticketStore;
        _userRepository = userRepository;
        _optionsService = optionsService;
    }

    public async Task<WebAuthnEnrollmentOptionsResult?> GenerateAsync(
        string? enrollmentToken,
        CancellationToken cancellationToken = default)
    {
        // 1. Identificar a conta associada ao token.
        var userId = _ticketStore.TryGetUserId(enrollmentToken);

        if (userId is null)
            return null;

        // 2. Confirmar que a conta existe no banco.
        var user = await _userRepository.GetByIdAsync(userId.Value);

        if (user is null)
            return null;

        // 3. Gerar e armazenar as opções WebAuthn.
        var (operationId, options) =
            await _optionsService.GenerateAsync(
                user,
                cancellationToken);

        // 4. Retornar os dados da operação.
        return new WebAuthnEnrollmentOptionsResult(
            operationId,
            options);
    }
}

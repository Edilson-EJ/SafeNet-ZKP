
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Application.Interfaces.Security;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.UseCases.WebAuthn.StartEnrollment;

public sealed record StartEnrollmentResult(
    Guid UserId,
    string Name,
    string EnrollmentToken,
    DateTime CreatedAt);

public sealed class StartEnrollmentUseCase
{
    private readonly IUserRepository _userRepository;
    private readonly IEnrollmentTicketIssuer _ticketIssuer;

    public StartEnrollmentUseCase(
        IUserRepository userRepository,
        IEnrollmentTicketIssuer ticketIssuer)
    {
        _userRepository = userRepository;
        _ticketIssuer = ticketIssuer;
    }

    public async Task<StartEnrollmentResult> ExecuteAsync(
        string name)
    {
        // 1. Criar uma nova conta.
        var user = new User(name);

        // 2. Persistir a conta no banco.
        await _userRepository.AddAsync(user);

        // 3. Emitir um token exclusivo para essa conta.
        var enrollmentToken = _ticketIssuer.Issue(user.Id);

        // 4. Retornar os dados da inscrição inicial.
        return new StartEnrollmentResult(
            user.Id,
            user.Name,
            enrollmentToken,
            user.CreatedAt);
    }
}

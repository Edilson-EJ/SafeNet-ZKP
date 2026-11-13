
namespace SafeNetZKP.Application.Interfaces.Security;

public interface IEnrollmentTicketIssuer
{
    string Issue(Guid userId);
}

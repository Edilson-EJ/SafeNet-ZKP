
namespace SafeNetZKP.Application.Interfaces.Security;

public interface ICurrentUserContext
{
    Guid? UserId { get; }
}

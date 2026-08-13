using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.Interfaces.Repositories;

namespace SafeNetZKP.Application.UseCases.Users.GetUserById;

public class GetUserByIdUseCase
{
    private readonly IUserRepository _userRepository;

    public GetUserByIdUseCase(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<CreateUserResponse?> ExecuteAsync(Guid id)
    {
        var user = await _userRepository.GetByIdAsync(id);

        if (user is null)
            return null;

        return new CreateUserResponse(
            user.Id,
            user.Name,
            user.CreatedAt);
    }
}
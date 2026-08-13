using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.UseCases.Users.CreateUser;

public class CreateUserUseCase
{
    private readonly IUserRepository _userRepository;

    public CreateUserUseCase(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<CreateUserResponse> ExecuteAsync(
        CreateUserRequest request)
    {
        var user = new User(request.Name);

        await _userRepository.AddAsync(user);

        return new CreateUserResponse(
            user.Id,
            user.Name,
            user.CreatedAt);
    }
}
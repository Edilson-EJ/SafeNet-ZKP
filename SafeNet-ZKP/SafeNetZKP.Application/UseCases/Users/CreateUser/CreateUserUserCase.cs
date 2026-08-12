using SafeNetZKP.Application.DTOs.Users;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.UseCases.Users.CreateUser;

public class CreateUserUseCase
{
    public CreateUserResponse Execute(CreateUserRequest request)
    {
        var user = new User(request.Name);

        return new CreateUserResponse(
            user.Id,
            user.Name,
            user.CreatedAt);
    }
}
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Infrastructure.Repositories;

public class InMemoryUserRepository : IUserRepository
{
    private readonly Dictionary<Guid, User> _users = new();

    public Task AddAsync(User user)
    {
        _users[user.Id] = user;

        return Task.CompletedTask;
    }

    public Task<User?> GetByIdAsync(Guid id)
    {
        _users.TryGetValue(id, out var user);

        return Task.FromResult(user);
    }
}
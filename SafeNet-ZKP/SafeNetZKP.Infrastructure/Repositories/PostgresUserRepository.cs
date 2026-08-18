using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.Interfaces.Repositories;
using SafeNetZKP.Domain.Entities;
using SafeNetZKP.Infrastructure.Persistence;

namespace SafeNetZKP.Infrastructure.Repositories;

public class PostgresUserRepository : IUserRepository
{
    private readonly SafeNetZkpDbContext _dbContext;

    public PostgresUserRepository(SafeNetZkpDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task AddAsync(User user)
    {
        await _dbContext.Users.AddAsync(user);
        await _dbContext.SaveChangesAsync();
    }

    public async Task<User?> GetByIdAsync(Guid id)
    {
        return await _dbContext.Users
            .FirstOrDefaultAsync(user => user.Id == id);
    }
}
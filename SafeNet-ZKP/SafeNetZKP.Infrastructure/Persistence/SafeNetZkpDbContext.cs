using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Infrastructure.Persistence;

public class SafeNetZkpDbContext : DbContext
{
    public SafeNetZkpDbContext( DbContextOptions<SafeNetZkpDbContext> options ) : base(options)
    { }

    public DbSet<User> Users => Set<User>();
}
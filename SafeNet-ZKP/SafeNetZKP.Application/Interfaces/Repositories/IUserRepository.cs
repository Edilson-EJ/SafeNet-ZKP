using System;
using System.Collections.Generic;
using System.Text;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Application.Interfaces.Repositories;


public interface IUserRepository
{
    Task AddAsync(User user);

    Task<User?> GetByIdAsync(Guid id);
}



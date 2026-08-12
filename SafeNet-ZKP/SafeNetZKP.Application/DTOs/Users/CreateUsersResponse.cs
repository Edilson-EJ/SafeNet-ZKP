using System;
using System.Collections.Generic;
using System.Text;



namespace SafeNetZKP.Application.DTOs.Users;

public sealed record CreateUserResponse(
    Guid Id,
    string Name,
    DateTime CreatedAt);

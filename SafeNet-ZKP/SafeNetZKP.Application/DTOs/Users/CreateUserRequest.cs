using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace SafeNetZKP.Application.DTOs.Users;

public sealed record CreateUserRequest(
    [Required]
    string Name);
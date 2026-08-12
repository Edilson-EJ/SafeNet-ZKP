using System;
using System.Collections.Generic;
using System.Text;

namespace SafeNetZKP.Domain.Entities
{
    public class User
    {
        public Guid Id { get; set; }

        public string Name { get; set; }

        public DateTime CreatedAt { get; set; }

        private User() 
        { 
            Name = string.Empty;
        } 

        public User(string name)
        {
            if(string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("O nome do usuário é obrigatório.", nameof(name));
            }

            Id = Guid.NewGuid();
            Name = name;
            CreatedAt = DateTime.UtcNow;
        }
    }
}

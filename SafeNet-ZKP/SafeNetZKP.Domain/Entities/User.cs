using System;

namespace SafeNetZKP.Domain.Entities
{
    public class User
    {
        public Guid Id { get; private set; }

        public string Name { get; private set; }

        public DateTime CreatedAt { get; private set; }

        private User()
        {
            Name = string.Empty;
        }

        public User(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException(
                    "O nome do usuário é obrigatório.",
                    nameof(name));
            }

            Id = Guid.NewGuid();
            Name = name;
            CreatedAt = DateTime.UtcNow;
        }

        public void ChangeName(string newName)
        {
            if (string.IsNullOrWhiteSpace(newName))
            {
                throw new ArgumentException(
                    "O nome do usuário é obrigatório.",
                    nameof(newName));
            }

            Name = newName;
        }
    }
}
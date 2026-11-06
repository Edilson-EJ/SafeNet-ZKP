
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Domain.Entities;

namespace SafeNetZKP.Infrastructure.Persistence;

public class SafeNetZkpDbContext : DbContext
{
    public SafeNetZkpDbContext(
        DbContextOptions<SafeNetZkpDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<WebAuthnCredential> WebAuthnCredentials
        => Set<WebAuthnCredential>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<WebAuthnCredential>(entity =>
        {
            entity.HasKey(c => c.Id);

            // Um usuário pode possuir várias credenciais.
            entity.HasOne<User>()
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Cascade);

            // Identificador da credencial.
            entity.Property(c => c.CredentialId)
                .HasField("_credentialId")
                .UsePropertyAccessMode(PropertyAccessMode.Field)
                .HasColumnType("bytea")
                .IsRequired();

            // Chave pública em formato COSE.
            entity.Property(c => c.PublicKeyCose)
                .HasField("_publicKeyCose")
                .UsePropertyAccessMode(PropertyAccessMode.Field)
                .HasColumnType("bytea")
                .IsRequired();

            // Contador de assinaturas.
            entity.Property(c => c.SignatureCounter)
                .HasConversion<long>()
                .HasColumnType("bigint");

            // Cada CredentialId deve ser único.
            entity.HasIndex(c => c.CredentialId)
                .IsUnique();
        });
    }
}

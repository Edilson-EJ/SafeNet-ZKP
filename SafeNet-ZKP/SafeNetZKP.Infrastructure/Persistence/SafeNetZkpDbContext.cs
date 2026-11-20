
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Domain.CaptivePortal;
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
    public DbSet<AuthenticatedSession> AuthenticatedSessions => Set<AuthenticatedSession>();
    public DbSet<NetworkAccessAssociation> NetworkAccessAssociations => Set<NetworkAccessAssociation>();
    public DbSet<NetworkAccessEntry> NetworkAccessOperations => Set<NetworkAccessEntry>();

    public DbSet<WebAuthnCredential> WebAuthnCredentials
        => Set<WebAuthnCredential>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        ConfigureNetworkAccess(modelBuilder);

        modelBuilder.Entity<AuthenticatedSession>(entity =>
        {
            entity.ToTable("AuthenticatedSessions", table =>
            {
                table.HasCheckConstraint("CK_AuthenticatedSessions_IdHashLength", "octet_length(\"IdHash\") = 32");
                table.HasCheckConstraint("CK_AuthenticatedSessions_Expiration", "\"ExpiresAt\" > \"CreatedAt\"");
            });
            entity.HasKey(session => session.IdHash);
            entity.Property(session => session.IdHash).ValueGeneratedNever();
            entity.HasIndex(session => session.ExpiresAt);
            entity.HasOne<User>().WithMany().HasForeignKey(session => session.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

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

    private static void ConfigureNetworkAccess(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<NetworkAccessAssociation>(entity =>
        {
            entity.ToTable("NetworkAccessAssociations", table =>
            {
                table.HasCheckConstraint("CK_NetworkAccessAssociations_SessionHash", "octet_length(\"SessionHash\") = 32");
                table.HasCheckConstraint("CK_NetworkAccessAssociations_Validity",
                    "\"Generation\" > 0 AND \"LastRevision\" >= 0 AND \"ExpiresAt\" > \"CreatedAt\"");
            });
            entity.Property(item => item.Id).ValueGeneratedNever();
            entity.Ignore(item => item.Connection);
            entity.HasIndex(item => new { item.GatewayId, item.ConnectionId, item.Generation }).IsUnique();
            entity.HasIndex(item => new { item.SessionHash, item.UserId });
        });
        modelBuilder.Entity<NetworkAccessEntry>(entity =>
        {
            entity.ToTable("NetworkAccessOperations", table =>
            {
                table.HasCheckConstraint("CK_NetworkAccessOperations_Validity",
                    "\"Revision\" > 0 AND \"ValidUntil\" > \"CreatedAt\" AND \"ValidUntil\" <= \"AccessUntil\"");
                table.HasCheckConstraint("CK_NetworkAccessOperations_Revocation",
                    "(\"RevocationId\" IS NULL AND \"RevocationState\" IS NULL AND \"RevocationQueuedAt\" IS NULL) OR " +
                    "(\"RevocationId\" IS NOT NULL AND \"RevocationState\" IS NOT NULL AND \"RevocationQueuedAt\" IS NOT NULL)");
            });
            entity.Property(item => item.Id).ValueGeneratedNever();
            entity.HasOne(item => item.Association).WithMany().HasForeignKey(item => item.AssociationId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasIndex(item => new { item.AssociationId, item.IdempotencyKey }).IsUnique();
            entity.HasIndex(item => new { item.AssociationId, item.Revision }).IsUnique();
            entity.HasIndex(item => item.GrantId).IsUnique();
            entity.HasIndex(item => item.RevocationId).IsUnique();
            entity.HasIndex(item => new { item.RevocationState, item.UpdatedAt });
        });
    }
}

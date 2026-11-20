using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SafeNetZKP.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddPersistentNetworkAccess : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NetworkAccessAssociations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GatewayId = table.Column<Guid>(type: "uuid", nullable: false),
                    ConnectionId = table.Column<Guid>(type: "uuid", nullable: false),
                    Generation = table.Column<long>(type: "bigint", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionHash = table.Column<byte[]>(type: "bytea", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastRevision = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkAccessAssociations", x => x.Id);
                    table.CheckConstraint("CK_NetworkAccessAssociations_SessionHash", "octet_length(\"SessionHash\") = 32");
                    table.CheckConstraint("CK_NetworkAccessAssociations_Validity", "\"Generation\" > 0 AND \"LastRevision\" >= 0 AND \"ExpiresAt\" > \"CreatedAt\"");
                });

            migrationBuilder.CreateTable(
                name: "NetworkAccessOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AssociationId = table.Column<Guid>(type: "uuid", nullable: false),
                    IdempotencyKey = table.Column<Guid>(type: "uuid", nullable: false),
                    GrantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Revision = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ValidUntil = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    AccessUntil = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    State = table.Column<int>(type: "integer", nullable: false),
                    GrantState = table.Column<int>(type: "integer", nullable: true),
                    ConfirmedUntil = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevocationId = table.Column<Guid>(type: "uuid", nullable: true),
                    RevocationState = table.Column<int>(type: "integer", nullable: true),
                    RevocationQueuedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkAccessOperations", x => x.Id);
                    table.CheckConstraint("CK_NetworkAccessOperations_Revocation", "(\"RevocationId\" IS NULL AND \"RevocationState\" IS NULL AND \"RevocationQueuedAt\" IS NULL) OR (\"RevocationId\" IS NOT NULL AND \"RevocationState\" IS NOT NULL AND \"RevocationQueuedAt\" IS NOT NULL)");
                    table.CheckConstraint("CK_NetworkAccessOperations_Validity", "\"Revision\" > 0 AND \"ValidUntil\" > \"CreatedAt\" AND \"ValidUntil\" <= \"AccessUntil\"");
                    table.ForeignKey(
                        name: "FK_NetworkAccessOperations_NetworkAccessAssociations_Associati~",
                        column: x => x.AssociationId,
                        principalTable: "NetworkAccessAssociations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessAssociations_GatewayId_ConnectionId_Generation",
                table: "NetworkAccessAssociations",
                columns: new[] { "GatewayId", "ConnectionId", "Generation" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessAssociations_SessionHash_UserId",
                table: "NetworkAccessAssociations",
                columns: new[] { "SessionHash", "UserId" });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessOperations_AssociationId_IdempotencyKey",
                table: "NetworkAccessOperations",
                columns: new[] { "AssociationId", "IdempotencyKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessOperations_AssociationId_Revision",
                table: "NetworkAccessOperations",
                columns: new[] { "AssociationId", "Revision" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessOperations_GrantId",
                table: "NetworkAccessOperations",
                column: "GrantId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessOperations_RevocationId",
                table: "NetworkAccessOperations",
                column: "RevocationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NetworkAccessOperations_RevocationState_UpdatedAt",
                table: "NetworkAccessOperations",
                columns: new[] { "RevocationState", "UpdatedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkAccessOperations");

            migrationBuilder.DropTable(
                name: "NetworkAccessAssociations");
        }
    }
}

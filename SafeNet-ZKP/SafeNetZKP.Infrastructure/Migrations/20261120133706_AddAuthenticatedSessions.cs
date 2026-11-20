using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SafeNetZKP.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthenticatedSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthenticatedSessions",
                columns: table => new
                {
                    IdHash = table.Column<byte[]>(type: "bytea", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticatedSessions", x => x.IdHash);
                    table.CheckConstraint("CK_AuthenticatedSessions_Expiration", "\"ExpiresAt\" > \"CreatedAt\"");
                    table.CheckConstraint("CK_AuthenticatedSessions_IdHashLength", "octet_length(\"IdHash\") = 32");
                    table.ForeignKey(
                        name: "FK_AuthenticatedSessions_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticatedSessions_ExpiresAt",
                table: "AuthenticatedSessions",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticatedSessions_UserId",
                table: "AuthenticatedSessions",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthenticatedSessions");
        }
    }
}

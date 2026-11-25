using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SafeNetZKP.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddGatewayObservations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GatewayObservations",
                columns: table => new
                {
                    GatewayId = table.Column<Guid>(type: "uuid", nullable: false),
                    Nonce = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ConnectionId = table.Column<Guid>(type: "uuid", nullable: false),
                    Generation = table.Column<long>(type: "bigint", nullable: false),
                    ObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GatewayObservations", x => new { x.GatewayId, x.Nonce });
                });

            migrationBuilder.CreateIndex(
                name: "IX_GatewayObservations_ExpiresAt",
                table: "GatewayObservations",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GatewayObservations");
        }
    }
}

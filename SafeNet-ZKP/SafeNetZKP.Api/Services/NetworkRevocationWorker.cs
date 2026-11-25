using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using SafeNetZKP.Application.UseCases.CaptivePortal;

namespace SafeNetZKP.Api.Services;

internal sealed class NetworkRevocationWorker(IServiceScopeFactory scopes, TimeProvider clock,
    ILogger<NetworkRevocationWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5), clock);
        logger.LogInformation("Worker de revogação iniciado.");
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var processor = scope.ServiceProvider.GetRequiredService<NetworkRevocationProcessor>();
                var batch = await processor.ProcessPendingAsync(32, stoppingToken);
                if (batch is not { Revoked: 0, Expired: 0, Indeterminate: 0 })
                    logger.LogInformation(
                        "Lote de revogação reconciliado. Revoked={Revoked} Expired={Expired} Indeterminate={Indeterminate}",
                        batch.Revoked, batch.Expired, batch.Indeterminate);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested &&
                exception is DbException or DbUpdateException { InnerException: DbException } or TimeoutException)
            {
                logger.LogWarning("A fila de revogação de rede está temporariamente indisponível.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

using System.Data.Common;
using SafeNetZKP.Application.UseCases.CaptivePortal;

namespace SafeNetZKP.Api.Services;

internal sealed class NetworkRevocationWorker(IServiceScopeFactory scopes, ILogger<NetworkRevocationWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var processor = scope.ServiceProvider.GetRequiredService<NetworkRevocationProcessor>();
                await processor.ProcessPendingAsync(32, stoppingToken);
            }
            catch (DbException) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning("A fila de revogação de rede está temporariamente indisponível.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

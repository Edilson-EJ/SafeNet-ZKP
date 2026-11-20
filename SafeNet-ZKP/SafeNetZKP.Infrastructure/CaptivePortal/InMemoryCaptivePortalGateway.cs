using System.Security.Cryptography;
using SafeNetZKP.Application.Interfaces.Gateways;
using SafeNetZKP.Domain.CaptivePortal;

namespace SafeNetZKP.Infrastructure.CaptivePortal;

public enum SimulatedAuthorizationBehavior
{
    Confirm,
    Deny,
    TimeoutAfterApplying
}

public sealed class InMemoryCaptivePortalGateway(TimeProvider clock)
    : ICaptivePortalGateway, ICaptivePortalAssociationGateway
{
    private readonly object _sync = new();
    private readonly Guid _gatewayId = Guid.NewGuid();
    private readonly Dictionary<Guid, ConnectionState> _connections = new();
    private readonly Dictionary<Guid, NetworkAccessGrant> _grants = new();
    private readonly Dictionary<Guid, Operation> _operations = new();

    // Somente o ambiente de simulação chama estes métodos de ingresso.
    public ObservedNetworkConnection ObserveConnection(TimeSpan lifetime,
        SimulatedAuthorizationBehavior behavior = SimulatedAuthorizationBehavior.Confirm)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        lock (_sync)
        {
            var key = new NetworkConnectionKey(_gatewayId, Guid.NewGuid(), 1);
            var observation = new ObservedNetworkConnection(key, clock.GetUtcNow().Add(lifetime));
            _connections.Add(key.ConnectionId, new ConnectionState(observation, behavior));
            return observation;
        }
    }

    public ObservedNetworkConnection Reconnect(ObservedNetworkConnection observation, TimeSpan lifetime)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        lock (_sync)
        {
            var now = clock.GetUtcNow();
            var connection = GetTrustedConnection(observation);
            var next = new ObservedNetworkConnection(
                observation.Key with { Generation = checked(observation.Key.Generation + 1) }, now.Add(lifetime));
            if (connection.LastGrantId is { } grantId && ReadGrant(grantId, now).State == NetworkAccessState.Authorized)
                _grants[grantId] = _grants[grantId] with { State = NetworkAccessState.Revoked };
            _connections[observation.Key.ConnectionId] = new ConnectionState(next, connection.Behavior);
            return next;
        }
    }

    public string IssueAssociationReference(ObservedNetworkConnection observation, TimeSpan lifetime)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        lock (_sync)
        {
            var now = clock.GetUtcNow();
            var connection = GetTrustedConnection(observation);
            if (connection.Association is not null || observation.ExpiresAt <= now)
                throw new InvalidOperationException("A conexão não pode iniciar uma associação.");

            var reference = RandomNumberGenerator.GetBytes(32);
            connection.ReferenceHash = SHA256.HashData(reference);
            connection.ReferenceExpiresAt = Earlier(now.Add(lifetime), observation.ExpiresAt);
            return Convert.ToHexString(reference);
        }
    }

    public NetworkAssociation? Associate(ObservedNetworkConnection observation, NetworkAssociationRequest request)
    {
        if (request.Reference is not { Length: 64 } reference || !reference.All(Uri.IsHexDigit) ||
            request.UserId == Guid.Empty || request.AuthenticatedSessionReference == Guid.Empty)
            return null;

        lock (_sync)
        {
            var now = clock.GetUtcNow();
            var connection = FindConnection(observation.Key);
            if (connection is null || !ReferenceEquals(connection.Observation, observation) ||
                connection.Association is not null ||
                connection.ReferenceExpiresAt <= now ||
                request.AuthenticatedSessionExpiresAt <= now ||
                connection.ReferenceHash is not { } hash ||
                !CryptographicOperations.FixedTimeEquals(hash, SHA256.HashData(Convert.FromHexString(reference))))
                return null;

            connection.ReferenceHash = null;
            connection.Association = new NetworkAssociation(observation.Key, request.UserId,
                request.AuthenticatedSessionReference, Earlier(request.AuthenticatedSessionExpiresAt, observation.ExpiresAt));
            return connection.Association;
        }
    }

    public Task<NetworkAssociation?> AssociateAsync(ObservedNetworkConnection observation,
        NetworkAssociationRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Associate(observation, request));
    }

    public Task<GatewayConnectionResult> GetSessionAsync(NetworkConnectionKey connection,
        CancellationToken cancellationToken) => ExecuteAsync<GatewayConnectionResult>(now =>
    {
        var match = FindConnection(connection);
        if (match is null || match.Observation.ExpiresAt <= now)
            return new(GatewayConnectionStatus.Missing);

        var grant = match.LastGrantId is { } grantId ? ReadGrant(grantId, now) : null;
        // A consulta retorna um retrato. Só o ingresso entrega a observação usada na associação.
        return new(GatewayConnectionStatus.Observed, match.Observation with { }, grant);
    }, cancellationToken);

    public Task<GatewayOperationResult> AuthorizeAsync(NetworkAuthorizationRequest request,
        CancellationToken cancellationToken) => ExecuteAsync(now =>
    {
        var connection = FindConnection(request.Association.Connection);
        if (connection is null || !ReferenceEquals(connection.Association, request.Association))
            return Denied(request.OperationId);
        if (FindDuplicate(request.OperationId, request, now) is { } duplicate)
            return duplicate;
        if (request.GrantId == Guid.Empty || request.OperationId == Guid.Empty ||
            request.Revision <= connection.Revision || request.ValidUntil <= now ||
            request.AccessUntil <= now || request.Association.ExpiresAt <= now ||
            _grants.ContainsKey(request.GrantId))
            return Denied(request.OperationId);

        connection.Revision = request.Revision;
        if (connection.Behavior == SimulatedAuthorizationBehavior.Deny ||
            (connection.LastGrantId is { } last && ReadGrant(last, now).State == NetworkAccessState.Authorized))
        {
            var denied = Denied(request.OperationId);
            _operations.Add(request.OperationId, new Operation(request, denied));
            return denied;
        }

        var grant = new NetworkAccessGrant(request.GrantId, request.Association.Connection,
            NetworkAccessState.Authorized, Earlier(request.AccessUntil, request.Association.ExpiresAt));
        _grants.Add(grant.Id, grant);
        connection.LastGrantId = grant.Id;
        var confirmed = new GatewayOperationResult(request.OperationId, NetworkAccessState.Authorized, grant);
        _operations.Add(request.OperationId, new Operation(request, confirmed));
        return connection.Behavior == SimulatedAuthorizationBehavior.TimeoutAfterApplying
            ? new GatewayOperationResult(request.OperationId, NetworkAccessState.Indeterminate)
            : confirmed;
    }, cancellationToken);

    public Task<GatewayOperationResult> GetOperationAsync(Guid gatewayId, Guid operationId,
        CancellationToken cancellationToken) => ExecuteAsync(now =>
        gatewayId == _gatewayId && _operations.TryGetValue(operationId, out var operation)
            ? ReadOperation(operation, now)
            : new GatewayOperationResult(operationId, NetworkAccessState.Indeterminate), cancellationToken);

    public Task<GatewayOperationResult> RevokeAsync(NetworkRevocationRequest request,
        CancellationToken cancellationToken) => ExecuteAsync(now =>
    {
        if (FindDuplicate(request.OperationId, request, now) is { } duplicate)
            return duplicate;
        var connection = FindConnection(request.Connection);
        if (connection is null || request.GrantId == Guid.Empty || request.OperationId == Guid.Empty ||
            request.Revision <= connection.Revision || request.ValidUntil <= now)
            return Denied(request.OperationId);
        if (_grants.TryGetValue(request.GrantId, out var grant) && grant.Connection != request.Connection)
            return Denied(request.OperationId);

        connection.Revision = request.Revision;
        grant = grant is null
            ? new NetworkAccessGrant(request.GrantId, request.Connection, NetworkAccessState.Revoked, null)
            : ReadGrant(grant.Id, now);
        if (grant.State == NetworkAccessState.Authorized)
            grant = grant with { State = NetworkAccessState.Revoked };

        // Registra também a revogação que chegou antes da autorização do mesmo ID.
        _grants[grant.Id] = grant;
        var result = new GatewayOperationResult(request.OperationId, grant.State, grant);
        _operations.Add(request.OperationId, new Operation(request, result));
        return result;
    }, cancellationToken);

    private ConnectionState? FindConnection(NetworkConnectionKey key) =>
        _connections.TryGetValue(key.ConnectionId, out var connection) && connection.Observation.Key == key
            ? connection : null;

    private ConnectionState GetTrustedConnection(ObservedNetworkConnection observation)
    {
        var connection = FindConnection(observation.Key);
        return connection is not null && ReferenceEquals(connection.Observation, observation)
            ? connection : throw new InvalidOperationException("Observação desconhecida ou obsoleta.");
    }

    private NetworkAccessGrant ReadGrant(Guid id, DateTimeOffset now)
    {
        var grant = _grants[id];
        if (grant.State == NetworkAccessState.Authorized && grant.ExpiresAt <= now)
            _grants[id] = grant = grant with { State = NetworkAccessState.Expired };
        return grant;
    }

    private GatewayOperationResult ReadOperation(Operation operation, DateTimeOffset now)
    {
        if (operation.Result.Grant is not { } snapshot)
            return operation.Result;

        var grant = ReadGrant(snapshot.Id, now);
        return operation.Result with { State = grant.State, Grant = grant };
    }

    private GatewayOperationResult? FindDuplicate(Guid id, object request, DateTimeOffset now) =>
        _operations.TryGetValue(id, out var operation)
            ? operation.Request.Equals(request) ? ReadOperation(operation, now) : Denied(id)
            : null;

    private Task<T> ExecuteAsync<T>(Func<DateTimeOffset, T> action, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (cancellationToken.IsCancellationRequested)
                return Task.FromCanceled<T>(cancellationToken);

            return Task.FromResult(action(clock.GetUtcNow()));
        }
    }

    private static GatewayOperationResult Denied(Guid id) => new(id, NetworkAccessState.Denied);

    private static DateTimeOffset Earlier(DateTimeOffset first, DateTimeOffset second) => first < second ? first : second;

    private sealed class ConnectionState(ObservedNetworkConnection observation, SimulatedAuthorizationBehavior behavior)
    {
        public ObservedNetworkConnection Observation { get; } = observation;
        public SimulatedAuthorizationBehavior Behavior { get; } = behavior;
        public byte[]? ReferenceHash { get; set; }
        public DateTimeOffset ReferenceExpiresAt { get; set; }
        public NetworkAssociation? Association { get; set; }
        public long Revision { get; set; }
        public Guid? LastGrantId { get; set; }
    }

    private sealed record Operation(object Request, GatewayOperationResult Result);
}

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Representation of a route firewall for use at runtime.
/// </summary>
internal sealed class RouteFirewallState
{
    private volatile RouteFirewallModel _model = default!;

    public RouteFirewallState(string routeId)
    {
#if NET7_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(routeId, nameof(routeId));
#else
        if (string.IsNullOrEmpty(routeId))
        {
            throw new ArgumentNullException(nameof(routeId));
        }
#endif
        RouteId = routeId;
    }

    public string RouteId { get; }

    /// <summary>
    /// Encapsulates parts of a route firewall that can change atomically
    /// in reaction to config changes.
    /// </summary>
    internal RouteFirewallModel Model
    {
        get => _model;
        set => _model = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Tracks changes to the route configuration for use with rebuilding the route firewall.
    /// </summary>
    internal int? RouteRevision { get; set; }
}

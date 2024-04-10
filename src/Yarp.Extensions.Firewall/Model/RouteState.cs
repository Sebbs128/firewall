using Yarp.ReverseProxy.Model;

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Representation of a route for use at runtime.
/// </summary>
public class RouteState
{
    private volatile RouteModel _model = default!;

    /// <summary>
    /// Creates a new instance for the given route name.
    /// </summary>
    /// <param name="routeId"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public RouteState(string routeId)
    {
        RouteId = routeId ?? throw new ArgumentNullException(nameof(routeId));
    }

    /// <summary>
    /// Creates a new instance for the given route name and route representation.
    /// </summary>
    /// <param name="routeId"></param>
    /// <param name="model"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public RouteState(string routeId, RouteModel model) : this(routeId)
    {
        Model = model ?? throw new ArgumentNullException(nameof(model));
    }

    /// <summary>
    /// The name of the route.
    /// </summary>
    public string RouteId { get; }

    /// <summary>
    /// Encapsulates parts of a route that can change atomically in reaction to config changes.
    /// </summary>
    public RouteModel Model
    {
        get => _model;
        internal set => _model = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Tracks changes to the configuration for use with rebuilding the route.
    /// </summary>
    internal int Revision { get; set; }
}

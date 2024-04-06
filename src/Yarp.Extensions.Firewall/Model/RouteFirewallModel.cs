using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Immutable representation of the portions of a route firewall
/// that only change in reaction to configuration changes.
/// </summary>
/// <remarks>
/// All members must remain immutable to avoid thread safety issues.
/// Instead, instances of <see cref="RouteFirewallModel"/> are replaced
/// in their entirety when values need to change.
/// </remarks>
public sealed class RouteFirewallModel
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public RouteFirewallModel(
        RouteFirewallConfig config,
        RouteState? route,
        RouteEvaluator evaluator)
    {
        Config = config ?? throw new ArgumentNullException(nameof(config));
        Route = route;
        Evaluator = evaluator ?? throw new ArgumentNullException(nameof(evaluator));
    }

    /// <summary>
    /// The <see cref="RouteState"/> instance associated with this route.
    /// </summary>
    public RouteState? Route { get; }

    /// <summary>
    /// The <see cref="RouteEvaluator"/> instance associated with this route.
    /// </summary>
    public RouteEvaluator Evaluator { get; }

    /// <summary>
    /// The configuration data used to build this firewall.
    /// </summary>
    public RouteFirewallConfig Config { get; }

    internal bool HasConfigChanged(RouteFirewallConfig newConfig, RouteState? route, int? firewallRevision)
    {
        return Route != route || firewallRevision != (route?.Revision) || !Config.Equals(newConfig);
    }
}

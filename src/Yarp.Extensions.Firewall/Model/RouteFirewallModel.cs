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
/// <remarks>
/// Creates a new instance.
/// </remarks>
public sealed class RouteFirewallModel(
    RouteFirewallConfig config,
    RouteState? route,
    RouteEvaluator evaluator)
{
    /// <summary>
    /// The <see cref="RouteState"/> instance associated with this route.
    /// </summary>
    public RouteState? Route { get; } = route;

    /// <summary>
    /// The <see cref="RouteEvaluator"/> instance associated with this route.
    /// </summary>
    public RouteEvaluator Evaluator { get; } = evaluator ?? throw new ArgumentNullException(nameof(evaluator));

    /// <summary>
    /// The configuration data used to build this firewall.
    /// </summary>
    public RouteFirewallConfig Config { get; } = config ?? throw new ArgumentNullException(nameof(config));

    internal bool HasConfigChanged(RouteFirewallConfig newConfig, RouteState? route, int? firewallRevision)
    {
        return Route != route || firewallRevision != (route?.Revision) || !Config.Equals(newConfig);
    }
}

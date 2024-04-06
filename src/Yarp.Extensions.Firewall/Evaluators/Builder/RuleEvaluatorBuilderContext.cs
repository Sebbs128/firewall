using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// State used when building firewall rules for the given route.
/// </summary>
public class RuleEvaluatorBuilderContext
{
    /// <summary>
    /// The route firewall the condtions will be associated with.
    /// </summary>
    public RouteFirewallConfig Firewall { get; init; } = default!;

    /// <summary>
    /// The route used by the route firewall.
    /// This may be null if the route firewall is not currently paired with a route.
    /// </summary>
    public RouteConfig? Route { get; init; } = default!;

    /// <summary>
    /// Add condition evaluators here for the given route firewall.
    /// </summary>
    public IList<ConditionBuilderContext> ConditionBuilders { get; } = [];
}

using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public class RuleEvaluatorBuilderContext
{
    public RouteFirewallConfig Firewall { get; init; } = default!;
    public RouteConfig? Route { get; init; } = default!;

    public IList<ConditionBuilderContext> ConditionBuilders { get; } = new List<ConditionBuilderContext>();
}
using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public class ConditionBuilderContext
{
    public IList<ConditionEvaluator> RuleConditions { get; } = new List<ConditionEvaluator>();
    public string RuleName { get; init; } = default!;
    public uint Priority { get; init; }
    public MatchAction Action { get; init; }
}
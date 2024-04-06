using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// State used when building condition evaluators for the given firewall rule.
/// </summary>
public class ConditionBuilderContext
{
    /// <summary>
    /// The collection of condition evaluators for the firewall rule.
    /// </summary>
    public IList<ConditionEvaluator> RuleConditions { get; } = [];

    /// <summary>
    /// The firewall rule name.
    /// </summary>
    public string RuleName { get; init; } = default!;

    /// <summary>
    /// The firewall rule priority.
    /// </summary>
    public uint Priority { get; init; }

    /// <summary>
    /// The firewall rule action when all conditions match a request.
    /// </summary>
    public MatchAction Action { get; init; }
}

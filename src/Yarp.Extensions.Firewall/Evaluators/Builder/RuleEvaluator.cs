using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Evaluates a a collection of condition evaluators.
/// </summary>
public sealed class RuleEvaluator
{
    internal RuleEvaluator(string ruleName, uint priority, MatchAction action,
        IList<ConditionEvaluator> conditionEvaluators)
    {
        ArgumentNullException.ThrowIfNull(conditionEvaluators);

        RuleName = ruleName;
        Priority = priority;
        Action = action;

        ConditionEvaluators = [.. conditionEvaluators];
    }

    internal string RuleName { get; }
    internal uint Priority { get; }
    internal MatchAction Action { get; }
    internal ConditionEvaluator[] ConditionEvaluators { get; }

    /// <summary>
    /// Evaluates the collection of condition evaluators
    /// </summary>
    /// <param name="context"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>True if all condition evaluators match the request, otherwise false.</returns>
    public async Task<bool> EvaluateRequestAsync(EvaluationContext context, CancellationToken cancellationToken)
    {
        foreach (var evaluator in ConditionEvaluators)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            // if any ConditionEvaluator returns false, then exit
            // conditions implicitly have an 'AND' between each
            if (!await evaluator.Evaluate(context, cancellationToken))
            {
                return false;
            }
        }

        return true;
    }
}

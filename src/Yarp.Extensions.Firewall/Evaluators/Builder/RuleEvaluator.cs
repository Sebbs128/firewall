using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public class RuleEvaluator
{
    internal RuleEvaluator(string ruleName, uint priority, MatchAction action,
        IList<ConditionEvaluator> conditionEvaluators)
    {
        ArgumentNullException.ThrowIfNull(conditionEvaluators);

        RuleName = ruleName;
        Priority = priority;
        Action = action;

        ConditionEvaluators = conditionEvaluators.ToArray();
    }

    internal string RuleName { get; }
    internal uint Priority { get; }
    internal MatchAction Action { get; }
    internal ConditionEvaluator[] ConditionEvaluators { get; }

    public async Task<bool> EvaluateRequestAsync(EvaluationContext context, CancellationToken cancellationToken)
    {
        foreach (var evaluator in ConditionEvaluators)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            // if any ConditionEvaluator returns false, then exit
            // conditions implicitly have an 'AND' between each
            if (!await evaluator.Evaluate(context, cancellationToken))
                return false;
        }

        return true;
    }
}

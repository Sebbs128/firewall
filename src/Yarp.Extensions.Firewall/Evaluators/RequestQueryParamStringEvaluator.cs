using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestQueryParamStringEvaluator : ConditionEvaluator<StringOperator>
{
    public RequestQueryParamStringEvaluator(string selector, StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Selector = selector;
        MatchValues = matchValues;
        Transforms = transforms;
    }

    public string Selector { get; }
    public IReadOnlyList<string> MatchValues { get; }
    public IReadOnlyList<Transform> Transforms { get; }

    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        if (context.HttpContext.Request.Query.TryGetValue(Selector, out var queryValues))
        {
            for (var i = 0; i < queryValues.Count; i++)
            {
                var query = queryValues[i];
                foreach (var transform in Transforms)
                {
                    query = StringUtilities.ApplyTransform(query, transform);
                }

                if (ConditionUtilities.EvaluateStringCondition(query, Operator, MatchValues, out var matchValue))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.QueryParam}{ConditionMatchType.String}",
                        OperatorName: Operator.ToString(),
                        MatchVariableValue: matchValue[..Math.Min(100, matchValue.Length)]));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

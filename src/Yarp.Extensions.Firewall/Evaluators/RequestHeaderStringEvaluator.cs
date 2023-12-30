using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestHeaderStringEvaluator : ConditionEvaluator<StringOperator>
{
    public RequestHeaderStringEvaluator(string selector, StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
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

        if (context.HttpContext.Request.Headers.TryGetValue(Selector, out var headerValues))
        {
            for (var i = 0; i < headerValues.Count; i++)
            {
                var requestHeader = headerValues[i];
                foreach (var transform in Transforms)
                {
                    requestHeader = StringUtilities.ApplyTransform(requestHeader, transform);
                }

                if (ConditionUtilities.EvaluateStringCondition(requestHeader, Operator, MatchValues, out var matchValue))
                {
                    isMatch = true;

                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.RequestHeader}{ConditionMatchType.String}",
                        OperatorName: Operator.ToString(),
                        MatchVariableValue: matchValue));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

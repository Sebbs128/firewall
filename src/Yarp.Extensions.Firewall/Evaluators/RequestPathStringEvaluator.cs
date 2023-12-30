using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestPathStringEvaluator : ConditionEvaluator<StringOperator>
{
    public RequestPathStringEvaluator(StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        MatchValues = matchValues;
        Transforms = transforms;
    }

    public IReadOnlyList<string> MatchValues { get; }
    public IReadOnlyList<Transform> Transforms { get; }

    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;
        var requestUri = context.HttpContext.Request.GetEncodedPathAndQuery();

        foreach (var transform in Transforms)
        {
            requestUri = StringUtilities.ApplyTransform(requestUri, transform);
        }

        if (ConditionUtilities.EvaluateStringCondition(requestUri, Operator, MatchValues, out var matchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestPath}{ConditionMatchType.String}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: matchValue));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

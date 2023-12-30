using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestMethodSizeEvaluator : ConditionEvaluator<NumberOperator>
{
    public RequestMethodSizeEvaluator(NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        MatchValue = matchValue;
        Negate = negate;

        // Lower and Upper transforms don't affect the string's length, so we can ignore them
        Transforms = transforms
            .Where(t => t is not Transform.Uppercase or Transform.Lowercase)
            .ToList();
    }

    public uint MatchValue { get; }
    public IReadOnlyList<Transform> Transforms { get; }

    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;
        var requestMethod = context.HttpContext.Request.Method;

        foreach (var transform in Transforms)
        {
            requestMethod = StringUtilities.ApplyTransform(requestMethod, transform);
        }

        if (ConditionUtilities.EvaluateSizeCondition(requestMethod?.Length, Operator, MatchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestMethod}{ConditionMatchType.Size}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: requestMethod!));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

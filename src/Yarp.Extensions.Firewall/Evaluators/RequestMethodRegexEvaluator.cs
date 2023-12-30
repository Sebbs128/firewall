using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestMethodRegexEvaluator : RegexConditionEvaluator
{
    public RequestMethodRegexEvaluator(IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms) : base(matchPatterns, negate)
    {
        Transforms = transforms;
    }

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

        if (MatchesAnyPatterns(requestMethod!, out var matchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestMethod}{ConditionMatchType.String}",
                OperatorName: nameof(StringOperator.Regex),
                MatchVariableValue: matchValue));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

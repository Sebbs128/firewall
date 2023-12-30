using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestPathRegexEvaluator : RegexConditionEvaluator
{
    public RequestPathRegexEvaluator(IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms)
        : base(matchPatterns, negate)
    {
        Transforms = transforms;
    }

    public IReadOnlyList<Transform> Transforms { get; }

    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var requestUri = context.HttpContext.Request.GetEncodedPathAndQuery();
        var isMatch = false;

        foreach (var transform in Transforms)
        {
            requestUri = StringUtilities.ApplyTransform(requestUri, transform);
        }

        if (MatchesAnyPatterns(requestUri, out var matchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestPath}{ConditionMatchType.String}",
                OperatorName: nameof(StringOperator.Regex),
                MatchVariableValue: matchValue[..Math.Min(100, matchValue.Length)]));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

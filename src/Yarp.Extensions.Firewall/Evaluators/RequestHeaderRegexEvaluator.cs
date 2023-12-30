using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestHeaderRegexEvaluator : RegexConditionEvaluator
{
    public RequestHeaderRegexEvaluator(string selector, IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms)
        : base(matchPatterns, negate)
    {
        Selector = selector;
        Transforms = transforms;
    }

    public string Selector { get; }
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

                if (MatchesAnyPatterns(requestHeader!, out var matchValue))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.RequestHeader}{ConditionMatchType.String}",
                        OperatorName: nameof(StringOperator.Regex),
                        MatchVariableValue: matchValue[..Math.Min(100, matchValue.Length)]));
                    break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

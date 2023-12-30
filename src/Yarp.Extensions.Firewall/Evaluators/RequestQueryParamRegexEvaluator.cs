using System.Text.RegularExpressions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestQueryParamRegexEvaluator : RegexConditionEvaluator
{
    public RequestQueryParamRegexEvaluator(string selector, IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms)
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

        if (context.HttpContext.Request.Query.TryGetValue(Selector, out var queryValues))
        {
            for (var i = 0; i < queryValues.Count; i++)
            {
                var query = queryValues[i];
                foreach (var transform in Transforms)
                {
                    query = StringUtilities.ApplyTransform(query, transform);
                }

                if (MatchesAnyPatterns(query!, out var matchValue))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.QueryParam}{ConditionMatchType.String}",
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

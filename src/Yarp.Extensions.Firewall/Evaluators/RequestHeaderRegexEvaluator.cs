using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates a HTTP header against a regular expression.
/// </summary>
/// <inheritdoc/>
public class RequestHeaderRegexEvaluator(string selector, IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms) : RegexConditionEvaluator(matchPatterns, negate)
{

    /// <summary>
    /// HTTP header name to evaluate.
    /// </summary>
    public string Selector { get; } = selector;

    /// <summary>
    /// Transformations to apply before evaluating.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; } = transforms;

    /// <inheritdoc/>
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
                        MatchVariableValue: StringUtilities.FromStart(matchValue, 100)));
                    break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

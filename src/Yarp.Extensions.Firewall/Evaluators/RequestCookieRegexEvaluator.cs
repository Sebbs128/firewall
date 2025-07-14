using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates a HTTP cookie against a regular expression.
/// </summary>
/// <inheritdoc/>
public class RequestCookieRegexEvaluator(string selector, IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms) : RegexConditionEvaluator(matchPatterns, negate)
{

    /// <summary>
    /// Cookie name to evaluate.
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

        if (context.HttpContext.Request.Cookies.TryGetValue(Selector, out var requestCookie))
        {
            foreach (var transform in Transforms)
            {
                requestCookie = StringUtilities.ApplyTransform(requestCookie, transform);
            }

            if (MatchesAnyPatterns(requestCookie!, out var matchValue))
            {
                isMatch = true;
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: $"{MatchVariable.Cookie}{ConditionMatchType.String}",
                    OperatorName: nameof(StringOperator.Regex),
                    MatchVariableValue: StringUtilities.FromStart(matchValue, 100)));
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

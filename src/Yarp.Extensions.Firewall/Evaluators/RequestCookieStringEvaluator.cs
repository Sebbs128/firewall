using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates a given request cookie against string values.
/// </summary>
public class RequestCookieStringEvaluator : ConditionEvaluator<StringOperator>
{
    /// <inheritdoc/>
    public RequestCookieStringEvaluator(string selector, StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Selector = selector;
        MatchValues = matchValues;
        Transforms = transforms;
    }

    /// <summary>
    /// Cookie name to evaluate.
    /// </summary>
    public string Selector { get; }

    /// <summary>
    /// Values to match against.
    /// </summary>
    public IReadOnlyList<string> MatchValues { get; }

    /// <summary>
    /// Transformations to apply before evaluating.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; }

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

            if (ConditionUtilities.EvaluateStringCondition(requestCookie, Operator, MatchValues, out var matchValue))
            {
                isMatch = true;
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: $"{MatchVariable.Cookie}{ConditionMatchType.String}",
                    OperatorName: Operator.ToString(),
                    MatchVariableValue: matchValue));

            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

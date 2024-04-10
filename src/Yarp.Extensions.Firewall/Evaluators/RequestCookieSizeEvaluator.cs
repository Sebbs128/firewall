using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the length of a given request cookie.
/// </summary>
public class RequestCookieSizeEvaluator : ConditionEvaluator<NumberOperator>
{
    /// <inheritdoc/>
    public RequestCookieSizeEvaluator(string selector, NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Selector = selector;
        MatchValue = matchValue;

        // Lower and Upper transforms don't affect the string's length, so we can ignore them
        Transforms = transforms
            .Where(t => t is not Transform.Uppercase or Transform.Lowercase)
            .ToList();
    }

    /// <summary>
    /// Cookie name to evaluate.
    /// </summary>
    public string Selector { get; }

    /// <summary>
    /// Value to compare against.
    /// </summary>
    public uint MatchValue { get; }

    /// <summary>
    /// Transformations to apply before evaluating.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; }

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;
        context.HttpContext.Request.Cookies.TryGetValue(Selector, out var requestCookie);

        foreach (var transform in Transforms)
        {
            requestCookie = StringUtilities.ApplyTransform(requestCookie, transform);
        }

        if (ConditionUtilities.EvaluateSizeCondition(requestCookie?.Length, Operator, MatchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.Cookie}{ConditionMatchType.Size}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: requestCookie!));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

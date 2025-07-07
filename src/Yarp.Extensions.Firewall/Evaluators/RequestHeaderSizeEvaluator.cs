using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the length of a given request header.
/// </summary>
/// <inheritdoc/>
public class RequestHeaderSizeEvaluator(string selector, NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms) : ConditionEvaluator<NumberOperator>(@operator, negate)
{

    /// <summary>
    /// HTTP header name to evaluate.
    /// </summary>
    public string Selector { get; } = selector;

    /// <summary>
    /// Value to compare against.
    /// </summary>
    public uint MatchValue { get; } = matchValue;

    /// <summary>
    /// Transformations to apply before evaluating.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; } = [.. transforms.Where(t => t is not Transform.Uppercase or Transform.Lowercase)];

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;
        var requestHeader = default(string);

        if (context.HttpContext.Request.Headers.TryGetValue(Selector, out var headerValues))
        {
            requestHeader = headerValues.ToString();
        }

        foreach (var transform in Transforms)
        {
            requestHeader = StringUtilities.ApplyTransform(requestHeader, transform);
        }

        if (ConditionUtilities.EvaluateSizeCondition(requestHeader?.Length, Operator, MatchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestHeader}{ConditionMatchType.Size}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: requestHeader!));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

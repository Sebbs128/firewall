using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the request method against string values.
/// </summary>
public class RequestMethodStringEvaluator : ConditionEvaluator<StringOperator>
{
    /// <inheritdoc/>
    public RequestMethodStringEvaluator(StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        MatchValues = matchValues;
        Transforms = transforms;
    }

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
        var requestMethod = context.HttpContext.Request.Method;

        foreach (var transform in Transforms)
        {
            requestMethod = StringUtilities.ApplyTransform(requestMethod, transform);
        }

        if (ConditionUtilities.EvaluateStringCondition(requestMethod, Operator, MatchValues, out var matchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestMethod}{ConditionMatchType.String}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: matchValue));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

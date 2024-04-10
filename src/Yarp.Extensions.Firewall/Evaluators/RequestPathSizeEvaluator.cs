using Microsoft.AspNetCore.Http.Extensions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the length of the URL path.
/// </summary>
public class RequestPathSizeEvaluator : ConditionEvaluator<NumberOperator>
{
    /// <inheritdoc/>
    public RequestPathSizeEvaluator(NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        MatchValue = matchValue;

        // Lower and Upper transforms don't affect the string's length, so we can ignore them
        Transforms = transforms
            .Where(t => t is not Transform.Uppercase or Transform.Lowercase)
            .ToList();
    }

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
        var requestUri = context.HttpContext.Request.GetEncodedPathAndQuery();

        foreach (var transform in Transforms)
        {
            // Lower and Upper transforms don't affect the string's length, so we can ignore them
            if (transform is Transform.Lowercase || transform is Transform.Uppercase)
                continue;

            requestUri = StringUtilities.ApplyTransform(requestUri, transform);
        }

        if (ConditionUtilities.EvaluateSizeCondition(requestUri?.Length, Operator, MatchValue))
        {
            isMatch = true;
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestPath}{ConditionMatchType.Size}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: requestUri!));
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

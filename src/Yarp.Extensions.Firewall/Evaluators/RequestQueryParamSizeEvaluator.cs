using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the length of a given query parameter.
/// </summary>
public class RequestQueryParamSizeEvaluator : ConditionEvaluator<NumberOperator>
{
    /// <inheritdoc/>
    public RequestQueryParamSizeEvaluator(string selector, NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms)
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
    /// Query parameter name to evaluate.
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

        if (context.HttpContext.Request.Query.TryGetValue(Selector, out var queryValues))
        {
            for (int i = 0; i < queryValues.Count; i++)
            {
                var query = queryValues[i];
                foreach (var transform in Transforms)
                {
                    query = StringUtilities.ApplyTransform(query, transform);
                }

                if (ConditionUtilities.EvaluateSizeCondition(query?.Length, Operator, MatchValue))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.QueryParam}{ConditionMatchType.Size}",
                        OperatorName: Operator.ToString(),
                        MatchVariableValue: query!));
                }

            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates a given request header against string values.
/// </summary>
public class RequestHeaderStringEvaluator : ConditionEvaluator<StringOperator>
{
    /// <inheritdoc/>
    public RequestHeaderStringEvaluator(string selector, StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Selector = selector;
        MatchValues = matchValues;
        Transforms = transforms;
    }

    /// <summary>
    /// HTTP header name to evaluate.
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

        if (context.HttpContext.Request.Headers.TryGetValue(Selector, out var headerValues))
        {
            for (var i = 0; i < headerValues.Count; i++)
            {
                var requestHeader = headerValues[i];
                foreach (var transform in Transforms)
                {
                    requestHeader = StringUtilities.ApplyTransform(requestHeader, transform);
                }

                if (ConditionUtilities.EvaluateStringCondition(requestHeader, Operator, MatchValues, out var matchValue))
                {
                    isMatch = true;

                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: $"{MatchVariable.RequestHeader}{ConditionMatchType.String}",
                        OperatorName: Operator.ToString(),
                        MatchVariableValue: matchValue));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

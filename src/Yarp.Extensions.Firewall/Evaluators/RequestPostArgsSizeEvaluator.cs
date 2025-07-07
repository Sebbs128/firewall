using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the length of a given POST parameter.
/// </summary>
/// <inheritdoc/>
public class RequestPostArgsSizeEvaluator(string selector, NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms) : ConditionEvaluator<NumberOperator>(@operator, negate)
{

    /// <summary>
    /// POST parameter name to evaluate.
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
    public override async ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        var contentType = context.HttpContext.Request.ContentType;
        // only applies to HTTP POST with application/x-www-form-urlencoded content type
        // see https://github.com/MicrosoftDocs/azure-docs/issues/101541
        if (HttpMethods.IsPost(context.HttpContext.Request.Method) &&
            string.Equals(contentType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var formCollection = await context.HttpContext.Request.ReadFormAsync(cancellationToken);
            if (formCollection is not null)
            {
                if (formCollection.TryGetValue(Selector, out var formValues))
                {
                    for (var i = 0; i < formValues.Count; i++)
                    {
                        var postArg = formValues[i];
                        foreach (var transform in Transforms)
                        {
                            postArg = StringUtilities.ApplyTransform(postArg, transform);
                        }

                        if (ConditionUtilities.EvaluateSizeCondition(postArg?.Length, Operator, MatchValue))
                        {
                            isMatch = true;
                            context.MatchedValues.Add(new EvaluatorMatchValue(
                                MatchVariableName: $"{MatchVariable.PostArgs}{ConditionMatchType.Size}",
                                OperatorName: Operator.ToString(),
                                MatchVariableValue: postArg!));
                        }
                    }
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return Negate ^ isMatch;
    }
}

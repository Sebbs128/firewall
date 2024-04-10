using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates a POST parameter against string values.
/// </summary>
public class RequestPostArgsStringEvaluator : ConditionEvaluator<StringOperator>
{
    /// <inheritdoc/>
    public RequestPostArgsStringEvaluator(string selector, StringOperator @operator, IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Selector = selector;
        MatchValues = matchValues;
        Transforms = transforms;
    }

    /// <summary>
    /// POST parameter name to evaluate.
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
    public override async ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        // Azure Front Door apparently only matches Content-Type 'application/x-www-form-urlencoded'?
        // https://github.com/MicrosoftDocs/azure-docs/issues/101541#issuecomment-1324561448
        if (HttpMethods.IsPost(context.HttpContext.Request.Method) && context.HttpContext.Request.HasFormContentType)
        {
            var formCollection = await context.HttpContext.Request.ReadFormAsync(cancellationToken);
            if (formCollection is not null)
            {
                if (formCollection.TryGetValue(Selector, out var formValue))
                {
                    string? postArg = formValue;
                    foreach (var transform in Transforms)
                    {
                        postArg = StringUtilities.ApplyTransform(postArg, transform);
                    }

                    if (ConditionUtilities.EvaluateStringCondition(postArg, Operator, MatchValues, out var matchValue))
                    {
                        isMatch = true;
                        context.MatchedValues.Add(new EvaluatorMatchValue(
                            MatchVariableName: $"{MatchVariable.PostArgs}{ConditionMatchType.String}",
                            OperatorName: Operator.ToString(),
                            MatchVariableValue: matchValue));
                    }
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return Negate ^ isMatch;
    }
}

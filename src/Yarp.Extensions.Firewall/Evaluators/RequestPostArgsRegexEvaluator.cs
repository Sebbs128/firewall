using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestPostArgsRegexEvaluator : RegexConditionEvaluator
{
    public RequestPostArgsRegexEvaluator(string selector, IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms)
        : base(matchPatterns, negate)
    {
        Selector = selector;
        Transforms = transforms;
    }

    public string Selector { get; }
    public IReadOnlyList<Transform> Transforms { get; }

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
            var formCollection = await context.HttpContext.Request.ReadFormAsync();
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

                        if (MatchesAnyPatterns(postArg!, out var matchValue))
                        {
                            isMatch = true;
                            context.MatchedValues.Add(new EvaluatorMatchValue(
                                MatchVariableName: $"{MatchVariable.PostArgs}{ConditionMatchType.String}",
                                OperatorName: nameof(StringOperator.Regex),
                                MatchVariableValue: matchValue[..Math.Min(100, matchValue.Length)]));
                        }
                    }
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return Negate ^ isMatch;
    }
}

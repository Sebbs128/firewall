using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestPostArgsEvaluatorTestss : ConditionExtensionsTestsBase
{
    private readonly StringConditionFactory _stringFactory = new(new LoggerFactory());

    [Theory]
    [MemberData(nameof(StringMatchData))]
    public async Task PostArgsStringEvaluator_ReturnsTrue_WhenMatches(
        StringMatchCondition evaluatorCondition,
        IFormCollection formCollection,
        string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestPostArgsStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.Form = formCollection;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("PostArgsString", evaluatorCondition.Operator.ToString(), expectedMatch));
    }

    public static TheoryData<StringMatchCondition, IFormCollection, string> StringMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.PostArgs,
                Selector = "a",
                Operator = StringOperator.Any,
            }, new FormCollection(new()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.PostArgs,
                Selector = "a",
                Operator = StringOperator.Equals,
                MatchValues = new[] { "1" }
            }, new FormCollection(new()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.PostArgs,
                Selector = "a",
                Operator = StringOperator.StartsWith,
                MatchValues = new[] { "1" }
            }, new FormCollection(new()
            {
                { "a", "123" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.PostArgs,
                Selector = "a",
                Operator = StringOperator.EndsWith,
                MatchValues = new[] { "1" }
            }, new FormCollection(new()
            {
                { "a", "321" }
            }), "1"
        }
    };
}

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.Extensions.Firewall.Common.Tests;
using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestHeaderEvaluatorTestss : ConditionExtensionsTestsBase
{
    private readonly StringConditionFactory _stringFactory = new(new LoggerFactory());

    [Theory]
    [MemberData(nameof(StringSingleMatchData))]
    public async Task HeaderStringEvaluator_ReturnsTrue_WhenMatches(
        StringMatchCondition evaluatorCondition,
        IHeaderDictionary headerDictionary,
        string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestHeaderStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        foreach (var item in headerDictionary)
        {
            httpContext.Request.Headers.Add(item);
        }

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestHeaderString", evaluatorCondition.Operator.ToString(), expectedMatch));
    }

    public static TheoryData<StringMatchCondition, IHeaderDictionary, string> StringSingleMatchData => new ()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestHeader,
                Selector = "a",
                Operator = StringOperator.Any,
            }, new HeaderDictionary(new Dictionary<string, StringValues>()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestHeader,
                Selector = "a",
                Operator = StringOperator.Equals,
                MatchValues = ["1"]
            },
            new HeaderDictionary(new Dictionary<string, StringValues>()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestHeader,
                Selector = "a",
                Operator = StringOperator.StartsWith,
                MatchValues = ["1"]
            },
            new HeaderDictionary(new Dictionary<string, StringValues>()
            {
                { "a", "123" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestHeader,
                Selector = "a",
                Operator = StringOperator.EndsWith,
                MatchValues = ["1"]
            },
            new HeaderDictionary(new Dictionary<string, StringValues>()
            {
                { "a", "321" }
            }), "1"
        }
    };
}

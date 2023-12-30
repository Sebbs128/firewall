using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Tests.Common;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestCookieEvaluatorTestss : ConditionExtensionsTestsBase
{
    private readonly StringConditionFactory _stringFactory = new();

    [Theory]
    [MemberData(nameof(StringSingleMatchData))]
    public async Task CookieStringEvaluator_ReturnsTrue_WhenMatches(
        StringMatchCondition evaluatorCondition,
        IRequestCookieCollection cookieCollection,
        string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestCookieStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.Cookies = cookieCollection;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("CookieString", evaluatorCondition.Operator.ToString(), expectedMatch));
    }

    public static TheoryData<StringMatchCondition, IRequestCookieCollection, string> StringSingleMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.Cookie,
                Selector = "a",
                Operator = StringOperator.Any,
            }, new RequestCookieCollection(new Dictionary<string, string>()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.Cookie,
                Selector = "a",
                Operator = StringOperator.Equals,
                MatchValues = new[] { "1" }
            },
            new RequestCookieCollection(new Dictionary<string, string>()
            {
                { "a", "1" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.Cookie,
                Selector = "a",
                Operator = StringOperator.StartsWith,
                MatchValues = new[] { "1" }
            },
            new RequestCookieCollection(new Dictionary<string, string>()
            {
                { "a", "123" }
            }), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.Cookie,
                Selector = "a",
                Operator = StringOperator.EndsWith,
                MatchValues = new[] { "1" }
            },
            new RequestCookieCollection(new Dictionary<string, string>()
            {
                { "a", "321" }
            }), "1"
        }
    };

}

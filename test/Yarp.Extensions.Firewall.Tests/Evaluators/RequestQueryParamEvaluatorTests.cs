using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Common.Tests;
using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestQueryParamEvaluatorTests : ConditionExtensionsTestsBase
{
    private readonly StringConditionFactory _stringFactory = new(new LoggerFactory());

    [Theory]
    [MemberData(nameof(StringSingleMatchData))]
    public async Task QueryParamStringEvaluator_ReturnsTrue_WhenMatches(
        StringMatchCondition evaluatorCondition,
        QueryString queryString,
        string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestQueryParamStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.QueryString = queryString;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("QueryParamString", evaluatorCondition.Operator.ToString(), expectedMatch));
    }

    public static TheoryData<StringMatchCondition, QueryString, string> StringSingleMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.QueryParam,
                Selector = "a",
                Operator = StringOperator.Any,
            }, QueryString.Create("a", "1"), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.QueryParam,
                Selector = "a",
                Operator = StringOperator.Equals,
                MatchValues = ["1"]
            }, QueryString.Create("a", "1"), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.QueryParam,
                Selector = "a",
                Operator = StringOperator.StartsWith,
                MatchValues = ["1"]
            }, QueryString.Create("a", "123"), "1"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.QueryParam,
                Selector = "a",
                Operator = StringOperator.EndsWith,
                MatchValues = ["1"]
            }, QueryString.Create("a", "321"), "1"
        }
    };
}

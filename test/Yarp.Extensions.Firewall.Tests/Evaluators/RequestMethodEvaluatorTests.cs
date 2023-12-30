using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestMethodEvaluatorTests : ConditionExtensionsTestsBase
{
    private readonly StringConditionFactory _stringFactory = new();

    [Theory]
    [InlineData("GET", StringOperator.Equals)]
    public async Task RequestMethodEvaluator_ReturnsTrue_WhenSingleMatchValueMatches(
        string requestMethod,
        StringOperator stringOperator)
    {
        var evaluatorCondition = new StringMatchCondition
        {
            MatchVariable = MatchVariable.RequestMethod,
            Operator = stringOperator,
            MatchValues = new[] { requestMethod }
        };

        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestMethodStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = requestMethod;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestMethodString", stringOperator.ToString(), requestMethod));
    }

    [Theory]
    [InlineData("POST", "GET", StringOperator.Equals)]
    public async Task RequestMethod_ReturnsTrue_WhenSingleMatchValueDoesNotMatch(
        string requestMethod,
        string evaluatorMethod,
        StringOperator stringOperator)
    {
        var evaluatorCondition = new StringMatchCondition
        {
            MatchVariable = MatchVariable.RequestMethod,
            Operator = stringOperator,
            Negate = true,
            MatchValues = new[] { requestMethod }
        };

        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestMethodStringEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = evaluatorMethod;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        var evalContext = new EvaluationContext(httpContext);

        // because evaluator has Negate set, we're expecting a "match" but no actual match value
        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Empty(evalContext.MatchedValues);
    }
}

using System.Text;

using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class RequestBodyEvaluatorTests : ConditionExtensionsTestsBase
{
    private readonly SizeConditionFactory _sizeFactory = new();
    private readonly StringConditionFactory _stringFactory = new();

    [Theory]
    [InlineData(NumberOperator.GreaterThan, 0u)]
    [InlineData(NumberOperator.GreaterThanOrEqual, 15u)]
    [InlineData(NumberOperator.LessThan, 16u)]
    [InlineData(NumberOperator.LessThanOrEqual, 15u)]
    public async Task BodySizeEvaluator_ReturnsTrue_WhenSingleValueMatches(NumberOperator numberOperator, uint matchValue)
    {
        var evaluatorCondition = new SizeMatchCondition
        {
            MatchVariable = MatchVariable.RequestBody,
            Operator = numberOperator,
            MatchValue = matchValue
        };

        var builderContext = ValidateAndBuild(_sizeFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodySizeEvaluator>(evaluator);
        
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = StringToStream("request content");

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
    }

    [Theory]
    [MemberData(nameof(StringAnyMatchData))]
    public async Task BodyStringEvaluator_ReturnsTrue_WhenMatchesAny(StringMatchCondition evaluatorCondition, Stream requestBody)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodyStringAnyEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = requestBody;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestBodyString", StringOperator.Any.ToString(), ""));
    }

    [Theory]
    [MemberData(nameof(StringEqualsMatchData))]
    public async Task BodyStringEvaluator_ReturnsTrue_WhenMatchesEquals(StringMatchCondition evaluatorCondition, Stream requestBody, string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodyStringEqualsEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = requestBody;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestBodyString", StringOperator.Equals.ToString(), expectedMatch));
    }

    [Theory]
    [MemberData(nameof(StringContainsMatchData))]
    public async Task BodyStringEvaluator_ReturnsTrue_WhenMatchesContains(StringMatchCondition evaluatorCondition, Stream requestBody, string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodyStringContainsEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = requestBody;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestBodyString", StringOperator.Contains.ToString(), expectedMatch));
    }

    [Theory]
    [MemberData(nameof(StringStartsWithMatchData))]
    public async Task BodyStringEvaluator_ReturnsTrue_WhenMatchesStartsWith(StringMatchCondition evaluatorCondition, Stream requestBody, string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodyStringStartsWithEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = requestBody;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestBodyString", StringOperator.StartsWith.ToString(), expectedMatch));
    }

    [Theory]
    [MemberData(nameof(StringEndsWithMatchData))]
    public async Task BodyStringEvaluator_ReturnsTrue_WhenMatchesEndsWith(StringMatchCondition evaluatorCondition, Stream requestBody, string expectedMatch)
    {
        var builderContext = ValidateAndBuild(_stringFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RequestBodyStringEndsWithEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";

        httpContext.Request.Body = requestBody;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RequestBodyString", StringOperator.EndsWith.ToString(), expectedMatch));
    }

    public static TheoryData<StringMatchCondition, Stream> StringAnyMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody
            }, StringToStream("request content")
        }
    };

    public static TheoryData<StringMatchCondition, Stream, string> StringEqualsMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.Equals,
                MatchValues = new List<string> { "request content" }
            }, StringToStream("request content"), "request content"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.Equals,
                MatchValues = new List<string> { "/ / / / / / " },
                Transforms = new List<Transform> { Transform.UrlDecode }
            }, StringToStream("%2F%20%2F%20%2F%20%2F%20%2F%20%2F%20"), "/ / / / / / "
        }
    };

    public static TheoryData<StringMatchCondition, Stream, string> StringContainsMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.Contains,
                MatchValues = new List<string> { "quest" }
            }, StringToStream("request content"), "request content"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.Contains,
                MatchValues = new List<string> { "/ / / / / / " },
                Transforms = new List<Transform> { Transform.UrlDecode }
            }, StringToStream("%2F%20%2F%20%2F%20%2F%20%2F%20%2F%20"), "/ / / / / / "
        }
    };

    public static TheoryData<StringMatchCondition, Stream, string> StringStartsWithMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.StartsWith,
                MatchValues = new List<string> { "request" }
            }, StringToStream("request content"), "request content"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.StartsWith,
                MatchValues = new List<string> { "/ / / / / / " },
                Transforms = new List<Transform> { Transform.UrlDecode }
            }, StringToStream("%2F%20%2F%20%2F%20%2F%20%2F%20%2F%20"), "/ / / / / / "
        }
    };

    public static TheoryData<StringMatchCondition, Stream, string> StringEndsWithMatchData => new()
    {
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.EndsWith,
                MatchValues = new List<string> { "content" }
            }, StringToStream("request content"), "request content"
        },
        {
            new StringMatchCondition
            {
                MatchVariable = MatchVariable.RequestBody,
                Operator = StringOperator.EndsWith,
                MatchValues = new List<string> { "/ / / / / / " },
                Transforms = new List<Transform> { Transform.UrlDecode }
            }, StringToStream("%2F%20%2F%20%2F%20%2F%20%2F%20%2F%20"), "/ / / / / / "
        }
    };

    private static MemoryStream StringToStream(string text)
    {
        return new MemoryStream(Encoding.UTF8.GetBytes(text));
    }
}

using System.Net;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

using Yarp.Extensions.Firewall.Common.Tests;
using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;

public class IPAddressEvaluatorTests : ConditionExtensionsTestsBase
{
    private readonly IPAddressConditionFactory _ipAddressFactory = new();

    [Theory]
    [MemberData(nameof(IPAddressData))]
    public async Task SocketIpAddressSingleEvaluator_ReturnsTrue_WhenRemoteAddressMatches(IReadOnlyList<IPAddress> ipAddresses, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            IPAddressOrRanges = string.Join(",", ipAddresses),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<SocketIpAddressSingleEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("SocketIpAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(IPRangeData))]
    public async Task SocketIpAddressRangeEvaluator_ReturnsTrue_WhenRemoteAddressMatches(IReadOnlyList<IPNetwork> ipAddressRanges, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            IPAddressOrRanges = string.Join(",", ipAddressRanges),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<SocketIpAddressRangeEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("SocketIpAddress", "InRange", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(IPAddressData))]
    public async Task RemoteIpAddressSingleEvaluator_ReturnsTrue_WhenRemoteAddressMatches(IReadOnlyList<IPAddress> ipAddresses, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            IPAddressOrRanges = string.Join(",", ipAddresses),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RemoteIpAddressSingleEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(XFFHeaderAddressData))]
    public async Task RemoteIpAddressSingleEvaluator_ReturnsTrue_WhenXForwardedForMatches(IReadOnlyList<IPAddress> ipAddresses, StringValues xForwardedForValues, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            IPAddressOrRanges = string.Join(",", ipAddresses),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RemoteIpAddressSingleEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.Headers.Append("X-Forwarded-For", xForwardedForValues);

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(IPRangeData))]
    public async Task RemoteIpAddressRangeEvaluator_ReturnsTrue_WhenRemoteAddressMatches(IReadOnlyList<IPNetwork> ipAddressRanges, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            IPAddressOrRanges = string.Join(",", ipAddressRanges),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RemoteIpAddressRangeEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "InRange", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(XFFHeaderRangeData))]
    public async Task RemoteIpAddressRangeEvaluator_ReturnsTrue_WhenXForwardedForMatches(IReadOnlyList<IPNetwork> ipAddressRanges, StringValues xForwardedForValues, string expectedMatch)
    {
        var evaluatorCondition = new IPAddressMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            IPAddressOrRanges = string.Join(",", ipAddressRanges),
        };

        var builderContext = ValidateAndBuild(_ipAddressFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<RemoteIpAddressRangeEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.Headers.AppendList("X-Forwarded-For", xForwardedForValues);

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "InRange", expectedMatch));
    }


    public static TheoryData<IReadOnlyList<IPAddress>, IPAddress, string> IPAddressData => new()
    {
        {
            [ new IPAddress([127, 0, 0, 1]) ],
            new([127, 0, 0, 1]),
            "127.0.0.1"
        }
    };

    public static TheoryData<IReadOnlyList<IPNetwork>, IPAddress, string> IPRangeData => new()
    {
        {
            [ new(new IPAddress([127, 0, 0, 1]), 32) ],
            new([127, 0, 0, 1]),
            "127.0.0.1/32"
        }
    };

    public static TheoryData<IReadOnlyList<IPAddress>, StringValues, string> XFFHeaderAddressData => new()
    {
        {
            [ new([127, 0, 0, 1]) ],
            new("127.0.0.1"),
            "127.0.0.1"
        }
    };

    public static TheoryData<IReadOnlyList<IPNetwork>, StringValues, string> XFFHeaderRangeData => new()
    {
        {
            [ new(new IPAddress([127, 0, 0, 1]), 32) ],
            new("127.0.0.1"),
            "127.0.0.1/32"
        }
    };
}

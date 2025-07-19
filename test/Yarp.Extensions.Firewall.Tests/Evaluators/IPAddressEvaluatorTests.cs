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
    [MemberData(nameof(ForwardedHeaderAddressData))]
    public async Task RemoteIpAddressSingleEvaluator_ReturnsTrue_WhenForwardedHeaderMatches(IReadOnlyList<IPAddress> ipAddresses, StringValues forwardedValues, string expectedMatch)
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
        httpContext.Request.Headers.Append("Forwarded", forwardedValues);

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(XFFHeaderAddressData))]
    public async Task RemoteIpAddressSingleEvaluator_ReturnsTrue_WhenXForwardedForHeaderMatches(IReadOnlyList<IPAddress> ipAddresses, StringValues xForwardedForValues, string expectedMatch)
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
    [MemberData(nameof(ForwardedHeaderRangeData))]
    public async Task RemoteIpAddressRangeEvaluator_ReturnsTrue_WhenForwardedHeaderMatches(IReadOnlyList<IPNetwork> ipAddressRanges, StringValues forwardedValues, string expectedMatch)
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
        httpContext.Request.Headers.AppendList("Forwarded", forwardedValues);

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("RemoteIpAddress", "InRange", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(XFFHeaderRangeData))]
    public async Task RemoteIpAddressRangeEvaluator_ReturnsTrue_WhenXForwardedForHeaderMatches(IReadOnlyList<IPNetwork> ipAddressRanges, StringValues xForwardedForValues, string expectedMatch)
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
            [ new([127, 0, 0, 1]) ],
            new([127, 0, 0, 1]),
            "127.0.0.1"
        }
    };

    public static TheoryData<IReadOnlyList<IPNetwork>, IPAddress, string> IPRangeData => new()
    {
        {
            [ new(new IPAddress([127, 0, 0, 1]), 32) ],
            new([127, 0, 0, 1]),
            "127.0.0.1"
        }
    };

    public static TheoryData<IReadOnlyList<IPAddress>, StringValues, string> ForwardedHeaderAddressData => new()
    {
        {
            [ new([127, 0, 0, 1]) ],
            new("for=127.0.0.1"),
            "127.0.0.1"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new("for=192.0.2.60:1006"),
            "192.0.2.60"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new("for=127.0.0.1, for=192.0.2.60:1006"),
            "192.0.2.60"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new(["for=127.0.0.1", "for=192.0.2.60:1006"]),
            "192.0.2.60"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new("for=[2001:db8:cafe::17]:4711"),
            "2001:db8:cafe::17"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new("for=192.0.2.60:1006, for=[2001:db8:cafe::17]:4711"),
            "2001:db8:cafe::17"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new(["for=192.0.2.60:1006", "for=[2001:db8:cafe::17]:4711"]),
            "2001:db8:cafe::17"
        }
    };

    public static TheoryData<IReadOnlyList<IPNetwork>, StringValues, string> ForwardedHeaderRangeData => new()
    {
        {
            [ new(new IPAddress([127, 0, 0, 1]), 32) ],
            new("for=127.0.0.1"),
            "127.0.0.1"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new("for=192.0.2.60:1006"),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new("for=127.0.0.1, for=192.0.2.60:1006"),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new(["for=127.0.0.1", "for=192.0.2.60:1006"]),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new("for=[2001:db8:cafe::17]:4711"),
            "2001:db8:cafe::17"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new("for=192.0.2.60:1006, for=[2001:db8:cafe::17]:4711"),
            "2001:db8:cafe::17"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new(["for=192.0.2.60:1006", "for=[2001:db8:cafe::17]:4711"]),
            "2001:db8:cafe::17"
        }
    };

    public static TheoryData<IReadOnlyList<IPAddress>, StringValues, string> XFFHeaderAddressData => new()
    {
        {
            [ new([127, 0, 0, 1]) ],
            new("127.0.0.1"),
            "127.0.0.1"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new("192.0.2.60"),
            "192.0.2.60"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new("127.0.0.1, 192.0.2.60"),
            "192.0.2.60"
        },
        {
            [ new([192, 0, 2, 60]) ],
            new(["127.0.0.1", "192.0.2.60"]),
            "192.0.2.60"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new("2001:db8:cafe::17"),
            "2001:db8:cafe::17"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new("192.0.2.60:1006, 2001:db8:cafe::17"),
            "2001:db8:cafe::17"
        },
        {
            [ new([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]) ],
            new(["192.0.2.60:1006", "2001:db8:cafe::17"]),
            "2001:db8:cafe::17"
        }
    };

    public static TheoryData<IReadOnlyList<IPNetwork>, StringValues, string> XFFHeaderRangeData => new()
    {
        {
            [ new(new IPAddress([127, 0, 0, 1]), 32) ],
            new("127.0.0.1"),
            "127.0.0.1"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new("192.0.2.60"),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new("127.0.0.1, 192.0.2.60"),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([192, 0, 0, 0]), 22) ],
            new(["127.0.0.1", "192.0.2.60"]),
            "192.0.2.60"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new("2001:db8:cafe::17"),
            "2001:db8:cafe::17"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new("192.0.2.60, 2001:db8:cafe::17"),
            "2001:db8:cafe::17"
        },
        {
            [ new(new IPAddress([0x20, 0x01, 0x0D, 0xB8, 0xCA, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 48) ],
            new(["192.0.2.60", "2001:db8:cafe::17"]),
            "2001:db8:cafe::17"
        }
    };
}

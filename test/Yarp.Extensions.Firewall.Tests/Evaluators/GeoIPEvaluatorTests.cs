using System.Net;
using System.Text;

using MaxMind.GeoIP2;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

using NSubstitute;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Tests.Common;

namespace Yarp.Extensions.Firewall.Tests.Evaluators;
public class GeoIPEvaluatorTests : ConditionExtensionsTestsBase
{
    private readonly GeoIPConditionFactory _geoIPConditionFactory;

    public GeoIPEvaluatorTests()
    {
        var dbReader = new DatabaseReader(TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));
        var tokenSource = new CancellationTokenSource();
        var provider = new GeoIPDatabaseProvider(dbReader, tokenSource.Token);
        var providerFactory = Substitute.For<IGeoIPDatabaseProviderFactory>();
        providerFactory.GetCurrent().Returns(provider);

        _geoIPConditionFactory = new GeoIPConditionFactory(providerFactory);
    }

    [Theory]
    [MemberData(nameof(IPAddressData))]
    public async Task GeoIPSocketAddressEvaluator_ReturnsTrue_WhenMatches(IReadOnlyList<string> countries, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            MatchCountryValues = countries,
        };

        var builderContext = ValidateAndBuild(_geoIPConditionFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<GeoIPSocketAddressEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("GeoIPSocketAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(IPAddressData))]
    public async Task GeoIPRemoteAddressEvaluator_ReturnsTrue_WhenMatches(IReadOnlyList<string> countries, IPAddress remoteAddress, string expectedMatch)
    {
        var evaluatorCondition = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            MatchCountryValues = countries,
        };

        var builderContext = ValidateAndBuild(_geoIPConditionFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<GeoIPRemoteAddressEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Connection.RemoteIpAddress = remoteAddress;

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("GeoIPRemoteAddress", "Equals", expectedMatch));
    }

    [Theory]
    [MemberData(nameof(XFFHeaderAddressData))]
    public async Task GeoIPRemoteAddressEvaluator_ReturnsTrue_WhenMatchesViaXForwardedForHeader(IReadOnlyList<string> countries, StringValues xForwardedForValues, string expectedMatch)
    {
        var evaluatorCondition = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.RemoteAddress,
            MatchCountryValues = countries,
        };

        var builderContext = ValidateAndBuild(_geoIPConditionFactory, evaluatorCondition);
        var evaluator = Assert.Single(builderContext.RuleConditions);

        Assert.IsType<GeoIPRemoteAddressEvaluator>(evaluator);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Method = "GET";
        httpContext.Request.Scheme = "http";
        httpContext.Request.Host = new HostString("example.com:3456");
        httpContext.Request.Path = "/";
        httpContext.Request.Headers.Append("X-Forwarded-For", xForwardedForValues);

        var evalContext = new EvaluationContext(httpContext);

        Assert.True(await evaluator.Evaluate(evalContext, CancellationToken.None));
        Assert.Single(evalContext.MatchedValues, new EvaluatorMatchValue("GeoIPRemoteAddress", "Equals", expectedMatch));
    }

    public static TheoryData<IReadOnlyList<string>, IPAddress, string> IPAddressData => new()
    {
        {
            new string[] { "United Kingdom" },
            new IPAddress(new byte[] { 81, 2, 69, 160 }),
            "United Kingdom"
        }
    };

    public static TheoryData<IReadOnlyList<string>, StringValues, string> XFFHeaderAddressData => new()
    {
        {
            new string[] { "United Kingdom" },
            new StringValues("81.2.69.160"),
            "United Kingdom"
        }
    };

}

using System.Net;
using System.Reflection;
using System.Text;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using NSubstitute;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Configuration.ConfigProvider;

namespace Yarp.Extensions.Firewall.Tests.Configuration.ConfigProvider;
public class ConfigurationConfigProviderTests
{
    #region JSON test configuration

    private readonly ConfigurationSnapshot _validConfigurationData = new ConfigurationSnapshot()
    {
        RouteFirewalls =
        {
            new RouteFirewallConfig
            {
                RouteId = "routeA",
                Enabled = true,
                Mode = FirewallMode.Prevention,
                RedirectUri = "https://localhost:10000/blocked",
                BlockedStatusCode = HttpStatusCode.Forbidden,
                Rules = new List<RuleConfig>
                {
                    new RuleConfig
                    {
                        RuleName = "stringAndSize",
                        Priority = 10,
                        Action = MatchAction.Block,
                        Conditions = new List<MatchCondition>
                        {
                            new StringMatchCondition
                            {
                                Operator = StringOperator.Contains,
                                MatchVariable = MatchVariable.QueryParam,
                                Selector = "a",
                                MatchValues = new[] { "1" },
                                Transforms = new[]
                                {
                                    Transform.Trim,
                                    Transform.UrlDecode,
                                    Transform.Uppercase,
                                }
                            },
                            new SizeMatchCondition
                            {
                                Operator = NumberOperator.GreaterThanOrEqual,
                                MatchVariable = MatchVariable.Cookie,
                                Selector = "b",
                                MatchValue = 100
                            }
                        }
                    },
                    new RuleConfig
                    {
                        RuleName = "ipAddress1",
                        Priority = 11,
                        Action = MatchAction.Allow,
                        Conditions = new List<MatchCondition>
                        {
                            new IPAddressMatchCondition
                            {
                                IPAddressOrRanges = "2001::abcd",
                                MatchVariable = IPMatchVariable.SocketAddress
                            }
                        }
                    }
                }
            },
            new RouteFirewallConfig
            {
                RouteId = "routeB",
                Enabled = true,
                Mode = FirewallMode.Detection,
                RedirectUri = "https://localhost:20000/blocked.html",
                BlockedStatusCode = HttpStatusCode.NotFound,
                Rules = new List<RuleConfig>
                {
                    new RuleConfig
                    {
                        RuleName = "ipAddress2",
                        Priority = 5,
                        Action = MatchAction.Allow,
                        Conditions = new List<MatchCondition>
                        {
                            new IPAddressMatchCondition
                            {
                                IPAddressOrRanges = "192.168.0.0/16",
                                MatchVariable = IPMatchVariable.RemoteAddress
                            }
                        }
                    }
                }
            }
        }
    };

    private const string _validJsonConfig = @"
{
    ""RouteFirewalls"": {
        ""routeA"": {
            ""Enabled"": true,
            ""Mode"": ""Prevention"",
            ""RedirectUri"": ""https://localhost:10000/blocked"",
            ""BlockedStatusCode"": ""Forbidden"",
            ""Rules"": {
                ""stringAndSize"": {
                    ""Priority"": 10,
                    ""Action"": ""Block"",
                    ""Conditions"": [
                        {
                            ""MatchType"": ""String"",
                            ""Operator"": ""Contains"",
                            ""MatchVariable"": ""QueryParam"",
                            ""Selector"": ""a"",
                            ""MatchValues"": [ ""1"" ],
                            ""Transforms"": [
                                ""Trim"",
                                ""UrlDecode"",
                                ""Uppercase""
                            ]
                        },
                        {
                            ""MatchType"": ""Size"",
                            ""Operator"": ""GreaterThanOrEqual"",
                            ""MatchVariable"": ""Cookie"",
                            ""Selector"": ""b"",
                            ""MatchValue"": 100
                        }
                    ]
                },
                ""ipAddress1"": {
                    ""Priority"": 11,
                    ""Action"": ""Allow"",
                    ""Conditions"": [
                        {
                            ""MatchType"": ""IPAddress"",
                            ""IPAddressOrRanges"": ""2001::abcd"",
                            ""MatchVariable"": ""SocketAddress""
                        }
                    ]
                }
            }
        },
        ""routeB"": {
            ""Enabled"": true,
            ""Mode"": ""Detection"",
            ""RedirectUri"": ""https://localhost:20000/blocked.html"",
            ""BlockedStatusCode"": ""NotFound"",
            ""Rules"": {
                ""ipAddress2"": {
                    ""Priority"": 5,
                    ""Action"": ""Allow"",
                        ""Conditions"": [
                        {
                            ""MatchType"": ""IPAddress"",
                            ""IPAddressOrRanges"": ""192.168.0.0/16"",
                            ""MatchVariable"": ""RemoteAddress""
                        }
                    ]
                }
            }
        }
    }
}
";

    #endregion

    [Fact]
    public void GetConfig_ValidSerializedConfiguration_ConvertToAbstractionsSuccessfully()
    {
        var builder = new ConfigurationBuilder();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(_validJsonConfig));
        var firewallConfig = builder.AddJsonStream(stream).Build();
        var logger = Substitute.For<ILogger<ConfigurationConfigProvider>>();

        var provider = new ConfigurationConfigProvider(firewallConfig, logger);
        Assert.NotNull(provider);
        var abstractConfig = provider.GetConfig();

        VerifyValidAbstractConfig(_validConfigurationData, abstractConfig);
    }

    [Fact]
    public void GetConfig_ValidConfiguration_AllAbstractionsPropertiesAreSet()
    {
        var builder = new ConfigurationBuilder();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(_validJsonConfig));
        var firewallConfig = builder.AddJsonStream(stream).Build();
        var logger = Substitute.For<ILogger<ConfigurationConfigProvider>>();

        var provider = new ConfigurationConfigProvider(firewallConfig, logger);
        var abstractConfig = (ConfigurationSnapshot)provider.GetConfig();

        var abstractionsNamespace = typeof(RouteFirewallConfig).Namespace;

        VerifyAllPropertiesAreSet(abstractConfig);

        // TODO:
        // can't just copy what Yarp.ReverseProxy.Tests has, as we expect eg. 0-valued enums and in some cases empty strings
        void VerifyFullyInitialized(object obj, string name)
        {
            switch (obj)
            {
                case null:
                    Assert.Fail($"Property {name} is not initialized.");
                    break;
                case Enum m:
                    Assert.NotEqual(0, (int)(object)m);
                    break;
            }
        }

        void VerifyAllPropertiesAreSet(object obj)
        {
            var properties = obj.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public).Cast<PropertyInfo>();
            foreach (var property in properties)
            {
                VerifyFullyInitialized(property.GetValue(obj), $"{property.DeclaringType.Name}.{property.Name}");
            }
        }
    }

    private void VerifyValidAbstractConfig(IFirewallConfig validConfig, IFirewallConfig abstractConfig)
    {
        Assert.NotNull(abstractConfig);
        Assert.Equal(2, abstractConfig.RouteFirewalls.Count);

        var firewall1 = validConfig.RouteFirewalls.First(f => f.RouteId == "routeA");
        Assert.Single(abstractConfig.RouteFirewalls.Where(f => f.RouteId == "routeA"));
        var abstractFirewall1 = abstractConfig.RouteFirewalls.Single(f => f.RouteId == "routeA");
        Assert.Equal(firewall1.Enabled, abstractFirewall1.Enabled);
        Assert.Equal(firewall1.Mode, abstractFirewall1.Mode);
        Assert.Equal(firewall1.RedirectUri, abstractFirewall1.RedirectUri);
        Assert.Equal(firewall1.BlockedStatusCode, abstractFirewall1.BlockedStatusCode);

        Assert.Equal(firewall1.Rules.Count, abstractFirewall1.Rules.Count);

        var rule1_1 = firewall1.Rules.First(r => r.RuleName == "stringAndSize");
        Assert.Single(abstractFirewall1.Rules.Where(r => r.RuleName == "stringAndSize"));
        var abstractRule1_1 = abstractFirewall1.Rules.Single(r => r.RuleName == "stringAndSize");
        Assert.Equal(rule1_1, abstractRule1_1);

        var rule1_2 = firewall1.Rules.First(r => r.RuleName == "ipAddress1");
        Assert.Single(abstractFirewall1.Rules.Where(r => r.RuleName == "ipAddress1"));
        var abstractRule1_2 = abstractFirewall1.Rules.Single(r => r.RuleName == "ipAddress1");
        Assert.Equal(rule1_2, abstractRule1_2);

        var firewall2 = validConfig.RouteFirewalls.First(f => f.RouteId == "routeB");
        Assert.Single(abstractConfig.RouteFirewalls.Where(f => f.RouteId == "routeB"));
        var abstractFirewall2 = abstractConfig.RouteFirewalls.Single(f => f.RouteId == "routeB");
        Assert.Equal(firewall2.Enabled, abstractFirewall2.Enabled);
        Assert.Equal(firewall2.Mode, abstractFirewall2.Mode);
        Assert.Equal(firewall2.RedirectUri, abstractFirewall2.RedirectUri);
        Assert.Equal(firewall2.BlockedStatusCode, abstractFirewall2.BlockedStatusCode);

        Assert.Equal(firewall2.Rules, abstractFirewall2.Rules);
    }
}

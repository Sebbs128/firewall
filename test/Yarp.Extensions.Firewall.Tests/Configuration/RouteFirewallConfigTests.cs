using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Tests.Configuration;

public class RouteFirewallConfigTests
{
    [Fact]
    public void RouteFirewallConfig_IsEqual_WhenSameValue()
    {
        var a = new RouteFirewallConfig()
        {
            RouteId = "r",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new RuleConfig()
                {
                    RuleName = "a",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };
        var b = new RouteFirewallConfig()
        {
            RouteId = "R",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new RuleConfig()
                {
                    RuleName = "A",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "A",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };
        var c = b with { }; // Clone

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void RouteFirewallConfig_IsNotEqual_WhenDifferentValue()
    {
        var a = new RouteFirewallConfig()
        {
            RouteId = "r",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new RuleConfig()
                {
                    RuleName = "a",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };
        var b = a with { RouteId = "different" };
        var c = a with { Enabled = false };
        var d = a with { Mode = FirewallMode.Detection };
        var e = a with { RedirectUri = "https://localhost:20000/blocked" };
        var f = a with { BlockedStatusCode = HttpStatusCode.NotFound };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(a.Equals(d));
        Assert.False(a.Equals(e));
        Assert.False(a.Equals(f));
    }

    [Fact]
    public void RouteFirewallConfig_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new RouteFirewallConfig().Equals(null));
    }

    [Fact]
    public void RouteFirewallConfig_CanBeJsonSerialized()
    {
        var a = new RouteFirewallConfig()
        {
            RouteId = "r",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new RuleConfig()
                {
                    RuleName = "a",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };

        var json = JsonSerializer.Serialize(a);
        var b = JsonSerializer.Deserialize<RouteFirewallConfig>(json);

        Assert.Equal(a, b);
    }
}

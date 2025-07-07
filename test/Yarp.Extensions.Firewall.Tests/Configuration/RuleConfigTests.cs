using System.Text.Json;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Tests.Configuration;

public class RuleConfigTests
{
    [Fact]
    public void RuleConfig_IsEqual_WhenSameValue()
    {
        var a = new RuleConfig()
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
        };
        var b = new RuleConfig()
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
        };
        var c = b with { }; // Clone

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void RuleConfig_IsNotEqual_WhenDifferentValue()
    {
        var a = new RuleConfig()
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
        };
        var b = a with { RuleName = "b" };
        var c = a with { Priority = 2 };
        var d = a with { Action = MatchAction.Block };
        var e = a with
        {
            Conditions =
            [
                new SizeMatchCondition
                {
                    Operator = NumberOperator.GreaterThan,
                    MatchVariable = MatchVariable.QueryParam,
                    Selector = "a",
                    MatchValue = 1
                }
            ]
        };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(a.Equals(d));
        Assert.False(a.Equals(e));
    }

    [Fact]
    public void RuleConfig_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new RuleConfig().Equals(null));
    }

    [Fact]
    public void RuleConfig_CanBeJsonSerialized()
    {
        var a = new RuleConfig()
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
                },
                new SizeMatchCondition
                {
                    Operator = NumberOperator.GreaterThan,
                    MatchVariable = MatchVariable.QueryParam,
                    Selector = "a",
                    MatchValue = 1
                },
                        new IPAddressMatchCondition
                {
                    IPAddressOrRanges = "2001::abcd",
                    MatchVariable = IPMatchVariable.SocketAddress
                }
            ]
        };

        var json = JsonSerializer.Serialize(a);
        var b = JsonSerializer.Deserialize<RuleConfig>(json);

        Assert.Equal(a, b);
    }
}

using System.Text.Json;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Tests.Configuration;

public class MatchConditionTests
{
    [Fact]
    public void StringMatchCondition_IsEqual_WhenSameValue()
    {
        var a = new StringMatchCondition
        {
            Operator = StringOperator.Contains,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValues = ["1"]
        };
        var b = new StringMatchCondition
        {
            Operator = StringOperator.Contains,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "A",
            MatchValues = ["1"]
        };
        var c = b with { };

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void StringMatchCondition_IsNotEqual_WhenDifferentValue()
    {
        var a = new StringMatchCondition
        {
            Operator = StringOperator.Contains,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValues = ["1"]
        };
        var b = a with { Operator = StringOperator.Equals };
        var c = a with { MatchVariable = MatchVariable.PostArgs };
        var d = a with { Selector = "b" };
        var e = a with { MatchValues = ["2"] };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(a.Equals(d));
        Assert.False(a.Equals(e));
    }

    [Fact]
    public void StringMatchCondition_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new StringMatchCondition().Equals(null));
    }

    [Fact]
    public void StringMatchCondition_CanBeJsonSerialized()
    {
        var a = new StringMatchCondition
        {
            Operator = StringOperator.Contains,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValues = ["1"]
        };

        var json = JsonSerializer.Serialize(a);
        var b = JsonSerializer.Deserialize<StringMatchCondition>(json);

        Assert.Equal(a, b);

        var c = JsonSerializer.Deserialize<MatchCondition>(json);
        Assert.Equal(a, c);
    }

    [Fact]
    public void SizeMatchCondition_IsEqual_WhenSameValue()
    {
        var a = new SizeMatchCondition
        {
            Operator = NumberOperator.GreaterThan,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValue = 1
        };
        var b = new SizeMatchCondition
        {
            Operator = NumberOperator.GreaterThan,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "A",
            MatchValue = 1
        };
        var c = b with { };

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void SizeMatchCondition_IsNotEqual_WhenDifferentValue()
    {
        var a = new SizeMatchCondition
        {
            Operator = NumberOperator.GreaterThan,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValue = 1
        };
        var b = a with { Operator = NumberOperator.GreaterThanOrEqual };
        var c = a with { MatchVariable = MatchVariable.PostArgs };
        var d = a with { Selector = "b" };
        var e = a with { MatchValue = 2 };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
        Assert.False(a.Equals(d));
        Assert.False(a.Equals(e));
    }

    [Fact]
    public void SizeMatchCondition_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new SizeMatchCondition().Equals(null));
    }

    [Fact]
    public void SizeMatchCondition_CanBeJsonSerialized()
    {
        var a = new SizeMatchCondition
        {
            Operator = NumberOperator.GreaterThan,
            MatchVariable = MatchVariable.QueryParam,
            Selector = "a",
            MatchValue = 1
        };

        var json = JsonSerializer.Serialize(a);
        var b = JsonSerializer.Deserialize<SizeMatchCondition>(json);

        Assert.Equal(a, b);

        var c = JsonSerializer.Deserialize<MatchCondition>(json);
        Assert.Equal(a, c);
    }

    [Fact]
    public void IPAddressMatchCondition_IsEqual_WhenSameValue()
    {
        var a = new IPAddressMatchCondition
        {
            IPAddressOrRanges = "2001::abcd",
            MatchVariable = IPMatchVariable.SocketAddress
        };
        var b = new IPAddressMatchCondition
        {
            IPAddressOrRanges = "2001::ABCD",
            MatchVariable = IPMatchVariable.SocketAddress
        };
        var c = b with { };

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void IPAddressMatchCondition_IsNotEqual_WhenDifferentValue()
    {
        var a = new IPAddressMatchCondition
        {
            IPAddressOrRanges = "2001::abcd",
        };
        var b = a with { IPAddressOrRanges = "2001::" };
        var c = a with { MatchVariable = IPMatchVariable.RemoteAddress };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
    }

    [Fact]
    public void IPAddressMatchCondition_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new IPAddressMatchCondition().Equals(null));
    }

    [Fact]
    public void IPAddressMatchCondition_CanBeJsonSerialized()
    {
        var a = new IPAddressMatchCondition
        {
            IPAddressOrRanges = "2001::abcd",
            MatchVariable = IPMatchVariable.SocketAddress
        };

        var json = JsonSerializer.Serialize(a);
        var b = JsonSerializer.Deserialize<IPAddressMatchCondition>(json);

        Assert.Equal(a, b);

        var c = JsonSerializer.Deserialize<MatchCondition>(json);
        Assert.Equal(a, c);
    }

    [Fact]
    public void GeoIPMatchCondition_IsEqual_WhenSameValue()
    {
        var a = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            MatchCountryValues =
            [
                "United Kingdom"
            ]
        };
        var b = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            MatchCountryValues =
            [
                "United Kingdom"
            ]
        };
        var c = b with { };

        Assert.True(a.Equals(b));
        Assert.True(a.Equals(c));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
    }

    [Fact]
    public void GeoIPMatchCondition_IsNotEqual_WhenDifferentValue()
    {
        var a = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            MatchCountryValues =
            [
                "United Kingdom"
            ]
        };
        var b = a with { MatchVariable = IPMatchVariable.RemoteAddress };
        var c = b with { MatchCountryValues = ["United States"] };

        Assert.False(a.Equals(b));
        Assert.False(a.Equals(c));
    }

    [Fact]
    public void GeoIPMatchCondition_IsNotEqual_WhenComparedToNull()
    {
        Assert.False(new GeoIPMatchCondition().Equals(null));
    }

    [Fact]
    public void GeoIPMatchCondition_CanBeJsonSerialized()
    {
        var a = new GeoIPMatchCondition
        {
            MatchVariable = IPMatchVariable.SocketAddress,
            MatchCountryValues =
            [
                "United Kingdom"
            ]
        };

        var json = JsonSerializer.Serialize(a);
        var b= JsonSerializer.Deserialize<GeoIPMatchCondition>(json);

        Assert.Equal(a, b);

        var c = JsonSerializer.Deserialize<MatchCondition>(json);
        Assert.Equal(a, c);
    }
}

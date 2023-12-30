using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Tests.Utilities;

public class ConditionUtilitiesTests
{
    [Theory]
    [MemberData(nameof(SingleValueMatches))]
    public void EvaluateStringCondition_ReturnsTrue_WhenSingleValueMatches(string value, StringOperator stringOperator, string matchValue, string expected)
    {
        Assert.True(ConditionUtilities.EvaluateStringCondition(value, stringOperator, new string[] { matchValue }, out var matchedValue));
        Assert.Equal(expected, matchedValue);
    }

    public static TheoryData<string, StringOperator, string, string> SingleValueMatches => new()
    {
        { "a", StringOperator.Any, "", "a" },
        { "a", StringOperator.Equals, "a", "a" },
        { "asd", StringOperator.Contains, "a", "a" },
        { "sad", StringOperator.Contains, "a" , "a" },
        { "dsa", StringOperator.Contains, "a" , "a" },
        { "asd", StringOperator.StartsWith, "a" , "a" },
        { "dsa", StringOperator.EndsWith, "a" , "a" },
        { "asd", StringOperator.Regex, @"\w+", "asd" },
    };
}

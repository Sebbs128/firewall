using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Utilities;

internal static class ConditionUtilities
{
    // prefer deterministic regex if available (.NET 7 and later)
    internal const RegexOptions RegexOpts =
#if NET7_0_OR_GREATER
    RegexOptions.CultureInvariant | RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.NonBacktracking;
#else
        RegexOptions.CultureInvariant | RegexOptions.Compiled | RegexOptions.ExplicitCapture;
#endif
    internal static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromSeconds(1);


    public static bool EvaluateStringCondition(string? value, StringOperator stringOperator, IReadOnlyList<string> matchValues, [NotNullWhen(true)] out string? matchedValue)
    {
        matchedValue = null;
        switch (stringOperator)
        {
            case StringOperator.Any:
                matchedValue = value;
                return !string.IsNullOrEmpty(value);
            case StringOperator.Equals:
                if (string.IsNullOrEmpty(value))
                    return false;

                foreach (var matchValue in matchValues)
                {
                    if (string.Equals(value, matchValue, StringComparison.Ordinal))
                    {
                        matchedValue = matchValue;
                        return true;
                    }
                }
                return false;
            case StringOperator.Contains:
                if (string.IsNullOrEmpty(value))
                    return false;

                foreach (var matchValue in matchValues)
                {
                    if (value.Contains(matchValue, StringComparison.Ordinal))
                    {
                        matchedValue = matchValue;
                        return true;
                    }
                }
                return false;
            case StringOperator.StartsWith:
                if (string.IsNullOrEmpty(value))
                    return false;

                foreach (var matchValue in matchValues)
                {
                    if (value.StartsWith(matchValue, StringComparison.Ordinal))
                    {
                        matchedValue = matchValue;
                        return true;
                    }
                }
                return false;
            case StringOperator.EndsWith:
                if (string.IsNullOrEmpty(value))
                    return false;

                foreach (var matchValue in matchValues)
                {
                    if (value.EndsWith(matchValue, StringComparison.Ordinal))
                    {
                        matchedValue = matchValue;
                        return true;
                    }
                }
                return false;
            case StringOperator.Regex:
                if (value is null)
                    return false;

                foreach (var matchValue in matchValues)
                {
                    // TODO: single-line mode?
                    //   This path isn't actually used by anything now, in favour of unique RegexEvaluators
                    var match = Regex.Match(value, matchValue, RegexOpts, RegexMatchTimeout);
                    if (match?.Success == true)
                    {
                        matchedValue = match.Value;
                        return true;
                    }
                }
                return false;
            default:
                throw new NotImplementedException(stringOperator.ToString());
        }
    }

    public static bool EvaluateSizeCondition(long? value, NumberOperator numberOperator, uint matchValue)
    {
        value ??= 0;

        return numberOperator switch
        {
            NumberOperator.LessThan => value < matchValue,
            NumberOperator.LessThanOrEqual => value <= matchValue,
            NumberOperator.GreaterThan => value > matchValue,
            NumberOperator.GreaterThanOrEqual => value >= matchValue,
            _ => throw new NotImplementedException(numberOperator.ToString())
        };
    }
}

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// The base class for regular expression evaluators.
/// </summary>
public abstract class RegexConditionEvaluator : ConditionEvaluator<StringOperator>
{
    /// <inheritdoc/>
    protected RegexConditionEvaluator(IReadOnlyList<string> matchPatterns, bool negate) : base(StringOperator.Regex, negate)
    {
        MatchPatterns = matchPatterns
            .Select(s => new Regex(s, ConditionUtilities.RegexOpts, RegexMatchTimeout))
            .ToList();
    }

    /// <summary>
    /// Limits time taken to evaluate a regular expression.
    /// </summary>
    protected virtual TimeSpan RegexMatchTimeout { get; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Regular expressions to match against.
    /// </summary>
    public IReadOnlyList<Regex> MatchPatterns { get; }

    /// <summary>
    /// Checks if the <paramref name="input"/> matches any <see cref="MatchPatterns"/>.
    /// </summary>
    /// <param name="input">The string to check for matches on.</param>
    /// <param name="matchValue">If a match is found, the part of <paramref name="input"/> matching the regular expression.</param>
    /// <returns>True if a match is found. Otherwise false.</returns>
    protected bool MatchesAnyPatterns(string input, [NotNullWhen(true)] out string? matchValue)
    {
        matchValue = null;

        foreach (var regex in MatchPatterns)
        {
            // use Regex.EnumerateMatches() if available, because it is allocation-free
#if NET7_0_OR_GREATER
            var enumerator = regex.EnumerateMatches(input);
            if (enumerator.MoveNext())
            {
                matchValue = input.Substring(enumerator.Current.Index, enumerator.Current.Length);
                return true;
            }
#else
            var match = regex.Match(input);
            if (match.Success)
            {
                matchValue = match.Value;
                return true;
            }
#endif
        }
        return false;
    }
}

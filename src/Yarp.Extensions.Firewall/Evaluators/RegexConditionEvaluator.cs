using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public abstract class RegexConditionEvaluator : ConditionEvaluator<StringOperator>
{
    protected RegexConditionEvaluator(IReadOnlyList<string> matchPatterns, bool negate) : base(StringOperator.Regex, negate)
    {
        MatchPatterns = matchPatterns
            .Select(s => new Regex(s, ConditionUtilities.RegexOpts, RegexMatchTimeout))
            .ToList();
    }

    protected virtual TimeSpan RegexMatchTimeout { get; } = TimeSpan.FromSeconds(1);

    public IReadOnlyList<Regex> MatchPatterns { get; }

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

using System.Text.Json.Serialization;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition used in rule matches.
/// </summary>
/// <remarks>
/// MatchCondition is subclassed to handle IP address, geo-filtering, and better handling match variable types
/// - rate limiting should be handled via Microsoft.AspNetCore.RateLimiting (Yarp uses this)
/// - IP address filtering should accept CIDR ranges
/// - allows for more strict validation
/// - according to https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-custom-rules-powershell?source=recommendations#custom-rule-based-on-http-parameters
///     some MatchVariables can have a Selector to specify the key the rule applies to (eg. Referer header)
/// </remarks>
// (TODO: implement validators. not every variable+operator combo is valid)
[JsonConverter(typeof(MatchConditionDiscriminator))]
public abstract record MatchCondition : IEquatable<MatchCondition>
{
    /// <summary>
    /// The type of value to be evaluated in the condition.
    /// </summary>
    public abstract ConditionMatchType MatchType { get; }

    /// <summary>
    /// Invert the result of the condition evaluation.
    /// </summary>
    public bool Negate { get; set; }

    /// <inheritdoc/>
    public virtual bool Equals(MatchCondition? other)
    {
        return other is not null
            && MatchType == other.MatchType
            && Negate == other.Negate;
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            MatchType,
            Negate);
    }
}

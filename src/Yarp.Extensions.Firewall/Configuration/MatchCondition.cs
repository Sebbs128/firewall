using System.Text.Json.Serialization;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

// MatchCondition is subclassed to handle IP address, geo-filtering, and better handling match variable types
// - rate limiting should be handled via Microsoft.AspNetCore.RateLimiting (Yarp uses this)
// - IP address filtering should accept CIDR ranges
// - allows for more strict validation (TODO: implement validators. not every variable+operator combo is valid)
// - according to https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-custom-rules-powershell?source=recommendations#custom-rule-based-on-http-parameters
//     some MatchVariables can have a Selector to specify the key the rule applies to (eg. Referer header)
[JsonConverter(typeof(MatchConditionDiscriminator))]
public abstract record MatchCondition
{
    public abstract ConditionMatchType MatchType { get; }
    public bool Negate { get; set; }

    public virtual bool Equals(MatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return MatchType == other.MatchType
            && Negate == other.Negate;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            MatchType,
            Negate);
    }
}

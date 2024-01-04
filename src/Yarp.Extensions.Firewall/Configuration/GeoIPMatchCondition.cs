using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;
public sealed record GeoIPMatchCondition : MatchCondition
{
    public override ConditionMatchType MatchType => ConditionMatchType.GeoIP;
    public IPMatchVariable? MatchVariable { get; init; }

    public IReadOnlyList<string> MatchCountryValues { get; init; } = Array.Empty<string>();

    public bool Eqals(GeoIPMatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return base.Equals(other)
            && MatchVariable == other.MatchVariable
            && CollectionEqualityHelper.Equals(MatchCountryValues, other.MatchCountryValues);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            CollectionEqualityHelper.GetHashCode(MatchCountryValues));
    }
}

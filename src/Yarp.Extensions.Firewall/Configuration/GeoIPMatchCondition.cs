using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition for MaxMind GeoIP2 Country-based matching.
/// </summary>
public sealed record GeoIPMatchCondition : MatchCondition, IEquatable<GeoIPMatchCondition>
{
    /// <inheritdoc/>
    public override ConditionMatchType MatchType => ConditionMatchType.GeoIP;

    /// <summary>
    /// The type of IP address to use from the request.
    /// This field is required.
    /// </summary>
    public IPMatchVariable? MatchVariable { get; init; }

    /// <summary>
    /// List of country names to match for the condition.
    /// </summary>
    public IReadOnlyList<string> MatchCountryValues { get; init; } = Array.Empty<string>();

    /// <inheritdoc/>
    public bool Equals(GeoIPMatchCondition? other)
    {
        return other is not null
            && base.Equals(other)
            && MatchVariable == other.MatchVariable
            && CollectionEqualityHelper.Equals(MatchCountryValues, other.MatchCountryValues);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            CollectionEqualityHelper.GetHashCode(MatchCountryValues));
    }
}

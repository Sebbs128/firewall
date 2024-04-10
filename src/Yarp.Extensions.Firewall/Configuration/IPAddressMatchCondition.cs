namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition for IP address matching.
/// </summary>
public sealed record IPAddressMatchCondition : MatchCondition, IEquatable<IPAddressMatchCondition>
{
    /// <inheritdoc/>
    public override ConditionMatchType MatchType => ConditionMatchType.IPAddress;

    /// <summary>
    /// The type of IP address to use from the request.
    /// This field is required.
    /// </summary>
    public IPMatchVariable? MatchVariable { get; init; }

    /// <summary>
    /// The IP addresses this condition matches, either as a single address, a comma-separated list, or CIDR notation
    /// </summary>
    public string IPAddressOrRanges { get; init; } = string.Empty;

    /// <inheritdoc/>
    public bool Equals(IPAddressMatchCondition? other)
    {
        return other is not null
            && base.Equals(other)
            && MatchVariable == other.MatchVariable
            && string.Equals(IPAddressOrRanges, other.IPAddressOrRanges, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            IPAddressOrRanges.GetHashCode(StringComparison.OrdinalIgnoreCase));
    }
}

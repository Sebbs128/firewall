namespace Yarp.Extensions.Firewall.Configuration;

public sealed record IPAddressMatchCondition : MatchCondition
{
    public override ConditionMatchType MatchType => ConditionMatchType.IPAddress;
    public IPMatchVariable? MatchVariable { get; init; }

    public string IPAddressOrRanges { get; init; } = string.Empty;

    public bool Equals(IPAddressMatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return base.Equals(other)
            && MatchVariable == other.MatchVariable
            && string.Equals(IPAddressOrRanges, other.IPAddressOrRanges, StringComparison.OrdinalIgnoreCase);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            IPAddressOrRanges.GetHashCode(StringComparison.OrdinalIgnoreCase));
    }
}

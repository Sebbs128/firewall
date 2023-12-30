using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

public sealed record RuleConfig
{
    public string RuleName { get; init; } = default!;

    public uint Priority { get; init; }

    public MatchAction Action { get; init; }

    public IReadOnlyList<MatchCondition> Conditions { get; init; } = new List<MatchCondition>();

    public bool Equals(RuleConfig? other)
    {
        if (other is null)
        {
            return false;
        }

        return string.Equals(RuleName, other.RuleName, StringComparison.OrdinalIgnoreCase)
            && Priority == other.Priority
            && Action == other.Action
            && CollectionEqualityHelper.Equals(Conditions, other.Conditions);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            RuleName.GetHashCode(StringComparison.OrdinalIgnoreCase),
            Priority,
            Action,
            CollectionEqualityHelper.GetHashCode(Conditions));
    }
}

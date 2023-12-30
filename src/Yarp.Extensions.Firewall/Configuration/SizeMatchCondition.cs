using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

public sealed record SizeMatchCondition : TransformableMatchCondition
{
    public override ConditionMatchType MatchType => ConditionMatchType.Size;
    public NumberOperator Operator { get; init; }

    public uint MatchValue { get; init; }

    public bool Equals(SizeMatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return base.Equals(other)
            && Operator == other.Operator
            && CollectionEqualityHelper.Equals(MatchValue, other.MatchValue);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            Operator,
            MatchValue);
    }
}

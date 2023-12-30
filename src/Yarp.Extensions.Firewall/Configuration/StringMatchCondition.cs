using System.Text.Json.Serialization;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

public sealed record StringMatchCondition : TransformableMatchCondition
{
    public override ConditionMatchType MatchType => ConditionMatchType.String;
    public StringOperator Operator { get; init; }

    public IReadOnlyList<string> MatchValues { get; init; } = Array.Empty<string>();

    public bool Equals(StringMatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return base.Equals(other)
            && Operator == other.Operator
            && CollectionEqualityHelper.Equals(MatchValues, other.MatchValues);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            Operator,
            CollectionEqualityHelper.GetHashCode(MatchValues));
    }
}

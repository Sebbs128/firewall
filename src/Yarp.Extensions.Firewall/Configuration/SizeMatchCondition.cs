using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition for size- or length-based matching.
/// </summary>
public sealed record SizeMatchCondition : TransformableMatchCondition
{
    /// <inheritdoc/>
    public override ConditionMatchType MatchType => ConditionMatchType.Size;

    /// <summary>
    /// The type of numerical comparison to perform.
    /// </summary>
    public NumberOperator Operator { get; init; }

    /// <summary>
    /// Target value to evaluate against.
    /// </summary>
    public uint MatchValue { get; init; }

    /// <inheritdoc/>
    public bool Equals(SizeMatchCondition? other)
    {
        return other is not null
            && base.Equals(other)
            && Operator == other.Operator
            && CollectionEqualityHelper.Equals(MatchValue, other.MatchValue);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            Operator,
            MatchValue);
    }
}

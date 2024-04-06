using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition for string-based matching.
/// </summary>
public sealed record StringMatchCondition : TransformableMatchCondition, IEquatable<StringMatchCondition>
{
    /// <inheritdoc/>
    public override ConditionMatchType MatchType => ConditionMatchType.String;

    /// <summary>
    /// The type of string comparison to perform.
    /// </summary>
    public StringOperator Operator { get; init; }

    /// <summary>
    /// Target values to evaluate against.
    /// </summary>
    public IReadOnlyList<string> MatchValues { get; init; } = Array.Empty<string>();

    /// <inheritdoc/>
    public bool Equals(StringMatchCondition? other)
    {
        return other is not null
            && base.Equals(other)
            && Operator == other.Operator
            && CollectionEqualityHelper.Equals(MatchValues, other.MatchValues);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            Operator,
            CollectionEqualityHelper.GetHashCode(MatchValues));
    }
}

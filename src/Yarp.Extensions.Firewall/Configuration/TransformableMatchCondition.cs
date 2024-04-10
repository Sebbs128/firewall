using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a condition used in rule matches that applies transformations before evaluating the condition.
/// </summary>
public abstract record TransformableMatchCondition : MatchCondition, IEquatable<TransformableMatchCondition>
{
    /// <summary>
    /// HTTP request property to use when evaluating the condition.
    /// This field is required.
    /// </summary>
    public MatchVariable? MatchVariable { get; init; }

    /// <summary>
    /// Collection key to obtain the value for evaluation from.
    /// Applies only to Cookie, RequestHeader, PostArgs, QueryParam <see cref="MatchVariable"/>s
    /// </summary>
    public string Selector { get; init; } = string.Empty;

    /// <summary>
    /// Ordered collection of transformations to apply.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; init; } = [];

    /// <inheritdoc/>
    public virtual bool Equals(TransformableMatchCondition? other)
    {
        return other is not null
            && base.Equals(other)
            && MatchVariable == other.MatchVariable
            && string.Equals(Selector, other.Selector, StringComparison.OrdinalIgnoreCase)
            && CollectionEqualityHelper.Equals(Transforms, other.Transforms);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            Selector.GetHashCode(StringComparison.OrdinalIgnoreCase),
            CollectionEqualityHelper.GetHashCode(Transforms));
    }
}

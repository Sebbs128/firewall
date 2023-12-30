using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

public abstract record TransformableMatchCondition : MatchCondition
{
    public MatchVariable? MatchVariable { get; init; }

    // Applies only to Cookie, RequestHeader, PostArgs, QueryParam
    public string Selector { get; init; } = string.Empty;
    public IReadOnlyList<Transform> Transforms { get; init; } = new List<Transform>();

    public virtual bool Equals(TransformableMatchCondition? other)
    {
        if (other is null)
        {
            return false;
        }

        return base.Equals(other)
            && MatchVariable == other.MatchVariable
            && string.Equals(Selector, other.Selector, StringComparison.OrdinalIgnoreCase)
            && CollectionEqualityHelper.Equals(Transforms, other.Transforms);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            base.GetHashCode(),
            MatchVariable,
            Selector.GetHashCode(StringComparison.OrdinalIgnoreCase),
            CollectionEqualityHelper.GetHashCode(Transforms));
    }
}

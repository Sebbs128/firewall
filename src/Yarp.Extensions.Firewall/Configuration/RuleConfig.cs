using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a firewall rule that evaluates incoming requests based on the <see cref="Conditions"/> criteria
/// and handles matching requests according to its <see cref="Action"/>.
/// </summary>
public sealed record RuleConfig : IEquatable<RuleConfig>
{
    /// <summary>
    /// An identifier for or description of the rule.
    /// This field is required.
    /// </summary>
    public string RuleName { get; init; } = default!;

    /// <summary>
    /// Importance of the rule over other rules.
    /// This field is required.
    /// </summary>
    public uint Priority { get; init; }

    /// <summary>
    /// The action to take should all <see cref="Conditions"/> match the request.
    /// This field is required.
    /// </summary>
    public MatchAction Action { get; init; }

    /// <summary>
    /// The list of conditions to evaluate for the rule.
    /// </summary>
    public IReadOnlyList<MatchCondition> Conditions { get; init; } = [];

    /// <inheritdoc/>
    public bool Equals(RuleConfig? other)
    {
        return other is not null
            && string.Equals(RuleName, other.RuleName, StringComparison.OrdinalIgnoreCase)
            && Priority == other.Priority
            && Action == other.Action
            && CollectionEqualityHelper.Equals(Conditions, other.Conditions);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            RuleName.GetHashCode(StringComparison.OrdinalIgnoreCase),
            Priority,
            Action,
            CollectionEqualityHelper.GetHashCode(Conditions));
    }
}

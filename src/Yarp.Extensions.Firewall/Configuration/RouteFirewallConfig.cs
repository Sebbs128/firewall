using System.Net;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Describes a firewall that evaluates incoming requests to the route identified by its <see cref="RouteId"/>,
/// handling them based on the <see cref="Rules"/> criteria.
/// </summary>
public sealed record RouteFirewallConfig : IEquatable<RouteFirewallConfig>
{
    /// <summary>
    /// The proxy route that this firewall should apply to.
    /// This field is required.
    /// </summary>
    public string RouteId { get; init; } = default!;

    /// <summary>
    /// Turns the firewall for the proxy route on and off.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Operating mode of the firewall.
    /// </summary>
    public FirewallMode Mode { get; init; } = FirewallMode.Detection;

    /// <summary>
    /// Location clients are redirected to when a rule matching a request has the Redirect action.
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// HTTP status code sent to clients when requests are blocked.
    /// </summary>
    public HttpStatusCode BlockedStatusCode { get; init; }


    /// <summary>
    /// The list of rules to comprising the firewall.
    /// </summary>
    public IReadOnlyList<RuleConfig> Rules { get; init; } = [];

    /// <inheritdoc/>
    public bool Equals(RouteFirewallConfig? other)
    {
        return other is not null
            && EqualsExcludingRules(other)
            && CollectionEqualityHelper.Equals(Rules, other.Rules);
    }

    internal bool EqualsExcludingRules(RouteFirewallConfig other)
    {
        return other is not null
            && string.Equals(RouteId, other.RouteId, StringComparison.OrdinalIgnoreCase)
            && Enabled == other.Enabled
            && Mode == other.Mode
            && string.Equals(RedirectUri, other.RedirectUri, StringComparison.OrdinalIgnoreCase)
            && BlockedStatusCode == other.BlockedStatusCode;
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            RouteId?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            Enabled,
            Mode,
            RedirectUri?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            BlockedStatusCode,
            CollectionEqualityHelper.GetHashCode(Rules));
    }
}

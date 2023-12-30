using System.Net;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration;

public sealed record RouteFirewallConfig
{
    public string RouteId { get; init; } = default!;

    public bool Enabled { get; init; } = true;

    public FirewallMode Mode { get; init; } = FirewallMode.Detection;

    public string? RedirectUri { get; init; }

    public HttpStatusCode BlockedStatusCode { get; init; }

    public IReadOnlyList<RuleConfig> Rules { get; init; } = new List<RuleConfig>();

    public bool Equals(RouteFirewallConfig? other)
    {
        if (other is null)
        {
            return false;
        }

        return EqualsExcludingRules(other)
            && CollectionEqualityHelper.Equals(Rules, other.Rules);
    }

    internal bool EqualsExcludingRules(RouteFirewallConfig other)
    {
        if (other is null)
        {
            return false;
        }

        return string.Equals(RouteId, other.RouteId, StringComparison.OrdinalIgnoreCase)
            && Enabled == other.Enabled
            && Mode == other.Mode
            && string.Equals(RedirectUri, other.RedirectUri, StringComparison.OrdinalIgnoreCase)
            && BlockedStatusCode == other.BlockedStatusCode;
    }

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

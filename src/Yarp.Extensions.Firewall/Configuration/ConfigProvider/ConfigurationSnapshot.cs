using Microsoft.Extensions.Primitives;

namespace Yarp.Extensions.Firewall.Configuration.ConfigProvider;

internal sealed class ConfigurationSnapshot : IFirewallConfig
{
    public List<RouteFirewallConfig> RouteFirewalls { get; internal set; } = new List<RouteFirewallConfig>();

    IReadOnlyList<RouteFirewallConfig> IFirewallConfig.RouteFirewalls => RouteFirewalls;

    public string GeoIPDatabasePath { get; internal set; } = string.Empty;

    public IChangeToken ChangeToken { get; internal set; } = default!;
}

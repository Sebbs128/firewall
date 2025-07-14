using Microsoft.Extensions.Primitives;

namespace Yarp.Extensions.Firewall.Configuration.ConfigProvider;

internal sealed class ConfigurationSnapshot : IFirewallConfig
{
    public List<RouteFirewallConfig> RouteFirewalls { get; internal set; } = [];

    IReadOnlyList<RouteFirewallConfig> IFirewallConfig.RouteFirewalls => RouteFirewalls;

    public Dictionary<Type, object> ConfigurationExtensions { get; internal set; } = [];

    IDictionary<Type, object> IFirewallConfig.ConfigurationExtensions => ConfigurationExtensions;

    public IChangeToken ChangeToken { get; internal set; } = default!;
}

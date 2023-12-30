using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Management;
internal class FirewallConfigManagerProxyChangeListener : IConfigChangeListener
{
    private readonly IServiceProvider _serviceProvider;
    private FirewallConfigManager _firewallConfigManager;
    private bool _firewallConfigInitialised;

    public FirewallConfigManagerProxyChangeListener(IServiceProvider serviceProvider)
    {
        // injecting IServiceProvider instead of FirewallConfigManager to avoid a circular dependency
        // ProxyConfigManager -> this (as IConfigChangeListener) -> FirewallConfigManager -> ProxyConfigManager (as IProxyStateLookup)
        _serviceProvider = serviceProvider;
    }

    public void ConfigurationApplied(IReadOnlyList<IProxyConfig> proxyConfigs)
    {
        // once FirewallConfigManager has done an initial load from config, it handles listening for config changes
        // so we only care about the first ConfigurationApplied event
        if (!_firewallConfigInitialised)
        {
            _firewallConfigManager ??= _serviceProvider.GetRequiredService<FirewallConfigManager>();
            _firewallConfigManager.InitialLoadAsync().GetAwaiter().GetResult();
            _firewallConfigInitialised = true;
        }
    }

    public void ConfigurationApplyingFailed(IReadOnlyList<IProxyConfig> proxyConfigs, Exception exception)
    {
    }

    public void ConfigurationLoaded(IReadOnlyList<IProxyConfig> proxyConfigs)
    {
    }

    public void ConfigurationLoadingFailed(IProxyConfigProvider configProvider, Exception exception)
    {
    }
}

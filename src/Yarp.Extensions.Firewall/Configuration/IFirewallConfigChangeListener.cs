namespace Yarp.Extensions.Firewall.Configuration;

public interface IFirewallConfigChangeListener
{
    void ConfigurationApplied(IReadOnlyList<IFirewallConfig> firewallConfigs);
    void ConfigurationApplyingFailed(IReadOnlyList<IFirewallConfig> firewallConfigs, Exception ex);
    void ConfigurationLoaded(IReadOnlyList<IFirewallConfig> firewallConfigs);
    void ConfigurationLoadingFailed(IFirewallConfigProvider provider, Exception ex);
}

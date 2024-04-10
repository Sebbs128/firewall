namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Allows subscribing to events notifying you when the configuration is loaded and applied, or when those actions fail.
/// </summary>
public interface IFirewallConfigChangeListener
{
    /// <summary>
    /// Invoked when an error occurs while loading the configuration.
    /// </summary>
    /// <param name="configProvider">The instance of the configuration provider that failed to provide the configuration.</param>
    /// <param name="exception">The thrown exception.</param>
    void ConfigurationLoadingFailed(IFirewallConfigProvider configProvider, Exception exception);

    /// <summary>
    /// Invoked once the configurations have been successfully loaded.
    /// </summary>
    /// <param name="firewallConfigs">The list of instances that have been loaded.</param>
    void ConfigurationLoaded(IReadOnlyList<IFirewallConfig> firewallConfigs);

    /// <summary>
    /// Invoked when an error occurs while applying the configuration.
    /// </summary>
    /// <param name="firewallConfigs">The list of instances that were being processed.</param>
    /// <param name="exception">The thrown exception.</param>
    void ConfigurationApplyingFailed(IReadOnlyList<IFirewallConfig> firewallConfigs, Exception exception);

    /// <summary>
    /// Invoked when an error occurs while loading the configuration.
    /// </summary>
    /// <param name="firewallConfigs">The list of instances that have been applied.</param>
    void ConfigurationApplied(IReadOnlyList<IFirewallConfig> firewallConfigs);
}

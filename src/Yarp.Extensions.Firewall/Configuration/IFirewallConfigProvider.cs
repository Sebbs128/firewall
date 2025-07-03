namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// A data source for firewall configuration.
/// </summary>
public interface IFirewallConfigProvider
{
    /// <summary>
    /// Returns the current firewall configuration.
    /// </summary>
    /// <returns></returns>
    public IFirewallConfig GetConfig();
}

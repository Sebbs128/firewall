using Microsoft.Extensions.Configuration;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Provides functionality to retrieve extensions to firewall configuration.
/// </summary>
public interface IFirewallConfigurationExtensionProvider
{
    /// <summary>
    /// The type of the extended configuration that this provider handles.
    /// </summary>
    public Type Type { get; }

    /// <summary>
    /// Retrieves the extended configuration for the firewall based on the provided configuration.
    /// </summary>
    /// <param name="configuration"></param>
    /// <returns></returns>
    public object GetExtendedConfiguration(IConfiguration configuration);
}

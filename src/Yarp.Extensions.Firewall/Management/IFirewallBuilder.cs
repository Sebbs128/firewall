using Microsoft.Extensions.DependencyInjection;

namespace Yarp.Extensions.Firewall.Management;

/// <summary>
/// Firewall builder interface.
/// </summary>
public interface IFirewallBuilder
{
    /// <summary>
    /// Gets the services collection.
    /// </summary>
    public IServiceCollection Services { get; }
}

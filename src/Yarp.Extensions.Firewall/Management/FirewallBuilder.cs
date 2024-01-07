using Microsoft.Extensions.DependencyInjection;

namespace Yarp.Extensions.Firewall.Management;
/// <summary>
/// Firewall builder for DI configuration.
/// </summary>
internal class FirewallBuilder : IFirewallBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FirewallBuilder"/> class.
    /// </summary>
    /// <param name="services"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public FirewallBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    public IServiceCollection Services { get; }
}

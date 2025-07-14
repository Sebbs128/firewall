using Microsoft.Extensions.DependencyInjection;

namespace Yarp.Extensions.Firewall.Management;
/// <summary>
/// Firewall builder for DI configuration.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="FirewallBuilder"/> class.
/// </remarks>
/// <param name="services"></param>
/// <exception cref="ArgumentNullException"></exception>
internal class FirewallBuilder(IServiceCollection services) : IFirewallBuilder
{
    /// <summary>
    /// Gets the services collection.
    /// </summary>
    public IServiceCollection Services { get; } = services ?? throw new ArgumentNullException(nameof(services));
}

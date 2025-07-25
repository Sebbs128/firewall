using Microsoft.Extensions.DependencyInjection;

using Yarp.Extensions.Firewall.Management;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Extensions for <see cref="IFirewallBuilder"/>
/// used to register firewall configurations.
/// </summary>
public static class InMemoryConfigProviderExtensions
{
    /// <summary>
    /// Adds an InMemoryConfigProvider
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="firewalls"></param>
    /// <param name="componentExtensions"></param>
    /// <returns></returns>
    public static IFirewallBuilder LoadFromMemory(this IFirewallBuilder builder, IReadOnlyList<RouteFirewallConfig> firewalls, IDictionary<Type, object> componentExtensions)
    {
        builder.Services.AddSingleton(new InMemoryConfigProvider(firewalls, componentExtensions));
        builder.Services.AddSingleton<IFirewallConfigProvider>(sp => sp.GetRequiredService<InMemoryConfigProvider>());
        return builder;
    }
}

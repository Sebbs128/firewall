using Microsoft.Extensions.DependencyInjection;

using Yarp.Extensions.Firewall.Management;

namespace Yarp.Extensions.Firewall.Configuration;

public static class InMemoryConfigProviderExtensions
{
    public static IFirewallBuilder LoadFromMemory(this IFirewallBuilder builder, IReadOnlyList<RouteFirewallConfig> firewalls, string geoIPDatabasePath)
    {
        builder.Services.AddSingleton(new InMemoryConfigProvider(firewalls, geoIPDatabasePath));
        builder.Services.AddSingleton<IFirewallConfigProvider>(sp => sp.GetRequiredService<InMemoryConfigProvider>());
        return builder;
    }
}

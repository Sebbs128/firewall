using Microsoft.Extensions.DependencyInjection;

namespace Yarp.Extensions.Firewall.Configuration;

public static class InMemoryConfigProviderExtensions
{
    public static IReverseProxyBuilder LoadFromMemory(this IReverseProxyBuilder builder, IReadOnlyList<RouteFirewallConfig> firewalls, string geoIPDatabasePath)
    {
        builder.Services.AddSingleton(new InMemoryConfigProvider(firewalls, geoIPDatabasePath));
        builder.Services.AddSingleton<IFirewallConfigProvider>(sp => sp.GetRequiredService<InMemoryConfigProvider>());
        return builder;
    }
}

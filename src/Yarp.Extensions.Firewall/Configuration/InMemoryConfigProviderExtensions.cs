using Microsoft.Extensions.DependencyInjection;

namespace Yarp.Extensions.Firewall.Configuration;

public static class InMemoryConfigProviderExtensions
{
    public static IReverseProxyBuilder LoadFromMemory(this IReverseProxyBuilder builder, IReadOnlyList<RouteFirewallConfig> firewalls)
    {
        builder.Services.AddSingleton(new InMemoryConfigProvider(firewalls));
        builder.Services.AddSingleton<IFirewallConfigProvider>(sp => sp.GetRequiredService<InMemoryConfigProvider>());
        return builder;
    }
}

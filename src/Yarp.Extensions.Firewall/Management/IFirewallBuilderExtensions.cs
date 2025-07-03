using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Management;
internal static class IFirewallBuilderExtensions
{
    public static IFirewallBuilder AddConfigBuilder(this IFirewallBuilder builder)
    {
        // Evaluator Builder
        builder.Services.AddSingleton<IEvaluatorBuilder, EvaluatorBuilder>();

        builder.Services.TryAddSingleton<IFirewallConfigValidator, ConfigValidator>();
        builder.Services.TryAddSingleton<IConfigChangeListener, FirewallConfigManagerProxyChangeListener>();

        return builder;
    }

    public static IFirewallBuilder AddConfigManager(this IFirewallBuilder builder)
    {
        builder.Services.TryAddSingleton<FirewallConfigManager>();
        builder.Services.TryAddSingleton<IFirewallStateLookup>(sp => sp.GetRequiredService<FirewallConfigManager>());
        return builder;
    }
}

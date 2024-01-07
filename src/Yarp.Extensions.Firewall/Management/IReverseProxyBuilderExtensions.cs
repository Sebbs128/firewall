using System.Diagnostics.CodeAnalysis;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Configuration.ConfigProvider;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Management;

public static class IReverseProxyBuilderExtensions
{
    public static IReverseProxyBuilder AddFirewall(this IReverseProxyBuilder builder)
    {
        // Condition Factories
        builder.AddConditionFactory<IPAddressConditionFactory>();
        builder.AddConditionFactory<SizeConditionFactory>();
        builder.AddConditionFactory<StringConditionFactory>();
        builder.AddConditionFactory<GeoIPConditionFactory>();

        // Evaluator Builder
        builder.Services.AddSingleton<IEvaluatorBuilder, EvaluatorBuilder>();

        // Config Manager
        builder.Services.TryAddSingleton<IFirewallConfigValidator, ConfigValidator>();
        builder.Services.TryAddSingleton<FirewallConfigManager>();
        builder.Services.TryAddSingleton<IFirewallStateLookup>(sp => sp.GetRequiredService<FirewallConfigManager>());
        builder.Services.TryAddSingleton<IConfigChangeListener, FirewallConfigManagerProxyChangeListener>();
        builder.Services.TryAddSingleton<IGeoIPDatabaseProviderFactory, GeoIPDatabaseProviderFactory>();

        return builder;
    }

    public static IReverseProxyBuilder LoadFirewallFromConfig(this IReverseProxyBuilder builder, IConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);

        builder.Services.AddSingleton<IFirewallConfigProvider>(sp =>
        {
            return new ConfigurationConfigProvider(config, sp.GetRequiredService<ILogger<ConfigurationConfigProvider>>());
        });

        return builder;
    }

    public static IReverseProxyBuilder AddConditionFactory<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>(this IReverseProxyBuilder builder) where T : class, IConditionFactory
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConditionFactory, T>());
        return builder;
    }
}

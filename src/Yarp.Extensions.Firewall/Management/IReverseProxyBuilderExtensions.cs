using System.Diagnostics.CodeAnalysis;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Configuration.ConfigProvider;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Management;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods for adding firewall services.
/// </summary>
public static class IReverseProxyBuilderExtensions
{
    /// <summary>
    /// Adds Firewall's services to Dependency Injection
    /// </summary>
    /// <param name="proxyBuilder"></param>
    /// <returns></returns>
    public static IFirewallBuilder AddFirewall(this IReverseProxyBuilder proxyBuilder)
    {
        var builder = new FirewallBuilder(proxyBuilder.Services);
        // Condition Factories
        builder
            .AddConditionFactory<IPAddressConditionFactory>()
            .AddConditionFactory<SizeConditionFactory>()
            .AddConditionFactory<StringConditionFactory>()
            .AddConditionFactory<GeoIPConditionFactory>();

        // Config Manager
        builder
            .AddConfigBuilder()
            .AddConfigManager();

        return builder;
    }

    /// <summary>
    /// Loads route firewalls from config.
    /// </summary>
    public static IFirewallBuilder LoadFromConfig(this IFirewallBuilder builder, IConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);

        builder.Services.AddSingleton<IFirewallConfigProvider>(sp =>
        {
            return new ConfigurationConfigProvider(config,
                sp.GetService<IEnumerable<IFirewallConfigurationExtensionProvider>>() ?? [],
                sp.GetRequiredService<ILogger<ConfigurationConfigProvider>>());
        });

        return builder;
    }

    /// <summary>
    /// Registers a singleton IConditionFactory service. Multiple factories are allowed and they will be run in registration order.
    /// </summary>
    /// <typeparam name="TFactory">A class that implements IConditionFactory.</typeparam>
    /// <returns></returns>
    public static IFirewallBuilder AddConditionFactory<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TFactory>(this IFirewallBuilder builder) where TFactory : class, IConditionFactory
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConditionFactory, TFactory>());
        return builder;
    }

    /// <summary>
    /// Adds a configuration extension provider of the specified type to the firewall builder.
    /// </summary>
    /// <typeparam name="T">The type of the configuration extension provider.</typeparam>
    /// <returns></returns>
    public static IFirewallBuilder AddConfigurationExtensionProvider<T>(this IFirewallBuilder builder)
        where T : class, IFirewallConfigurationExtensionProvider
    {
        builder.Services.AddSingleton<IFirewallConfigurationExtensionProvider, T>();
        return builder;
    }
}

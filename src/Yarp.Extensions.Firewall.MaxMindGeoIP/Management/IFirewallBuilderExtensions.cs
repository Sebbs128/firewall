using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.MaxMindGeoIP;
using Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Yarp.Extensions.Firewall.Management;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Extension methods for adding MaxMind GeoIP services to the firewall builder.
/// </summary>
public static class IFirewallBuilderExtensions
{
    /// <summary>
    /// Adds the MaxMind GeoIP database provider to the firewall builder.
    /// </summary>
    /// <remarks>This method registers the necessary services for using MaxMind GeoIP functionality within the
    /// firewall. Ensure that the required MaxMind GeoIP database files are available and properly configured in the
    /// application.</remarks>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static IFirewallBuilder AddMaxMindGeoIP(this IFirewallBuilder builder)
    {
        // GeoIP Database Provider Factory
        builder.Services.TryAddSingleton<IGeoIPDatabaseProviderFactory, GeoIPDatabaseProviderFactory>();
        builder.AddConfigurationExtensionProvider<GeoIPDatabaseConfigurationExtensionProvider>();

        return builder;
    }
}

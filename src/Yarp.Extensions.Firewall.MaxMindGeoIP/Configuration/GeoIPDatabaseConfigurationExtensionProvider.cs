using Microsoft.Extensions.Configuration;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;

internal sealed class GeoIPDatabaseConfigurationExtensionProvider : FirewallConfigurationExtensionProvider<GeoIPDatabaseConfig>
{
    public override object GetExtendedConfiguration(IConfiguration configuration)
    {
        var configSection = configuration.GetSection(nameof(GeoIPDatabaseConfig));
        return new GeoIPDatabaseConfig
        {
            GeoIPDatabasePath = configSection.GetValue<string>(nameof(GeoIPDatabaseConfig.GeoIPDatabasePath)) ?? string.Empty
        };
    }
}

using Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Tests.Common;
internal static class TestResources
{
    public static string GetGeoIPDatabasePath(string fileName) => Path.Combine("GeoIP2 Databases", fileName);

    public static GeoIPDatabaseConfig GetGeoIPDatabaseConfig(string fileName)
    {
        return new GeoIPDatabaseConfig
        {
            GeoIPDatabasePath = GetGeoIPDatabasePath(fileName)
        };
    }
}

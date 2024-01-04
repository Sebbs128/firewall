namespace Yarp.Extensions.Firewall.Tests.Common;
public static class TestResources
{
    public static string GetGeoIPDatabasePath(string fileName) => Path.Combine("GeoIP2 Databases", fileName);
}

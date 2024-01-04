namespace Yarp.Extensions.Firewall.GeoIP;

public interface IGeoIPDatabaseProviderFactory
{
    GeoIPDatabaseProvider GetCurrent();
}

using System.Net;

using Yarp.Extensions.Firewall.GeoIP;

namespace Yarp.Extensions.Firewall.Common.Tests.GeoIP;
public sealed class DummyGeoIPDatabaseProvider : IGeoIPDatabaseProvider
{
    public void Dispose()
    {
    }

    public Country? LookupCountry(IPAddress ipAddress) => null;
}

public class DummyGeoIPDatabaseProviderFactory : IGeoIPDatabaseProviderFactory
{
    public IGeoIPDatabaseProvider GetCurrent() => new DummyGeoIPDatabaseProvider();
}

using Microsoft.Extensions.Logging;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Utilities;

internal static class EventIds
{
    public static readonly EventId GeoIPDatabaseOpened = new(20, "GeoIPDatabaseOpened");
}

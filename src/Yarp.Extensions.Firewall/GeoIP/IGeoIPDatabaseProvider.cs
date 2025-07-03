using System.Net;

namespace Yarp.Extensions.Firewall.GeoIP;

/// <summary>
/// An abstraction for GeoIP database providers.
/// </summary>
public interface IGeoIPDatabaseProvider : IDisposable
{
    /// <summary>
    /// Look up the country for the given IP address.
    /// </summary>
    /// <param name="ipAddress">IP address to look up.</param>
    /// <returns>
    /// The <see cref="Country"/> for the given IP address, or <c>null</c> if the country could not be determined.
    /// </returns>
    public Country? LookupCountry(IPAddress ipAddress);
}

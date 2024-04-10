namespace Yarp.Extensions.Firewall.GeoIP;

/// <summary>
/// A factory to retrieve the current instance of a <see cref="GeoIPDatabaseProvider"/>.
/// </summary>
public interface IGeoIPDatabaseProviderFactory
{
    /// <summary>
    /// The current active provider of MaxMind GeoIP2 database readers.
    /// </summary>
    /// <returns></returns>
    GeoIPDatabaseProvider GetCurrent();
}

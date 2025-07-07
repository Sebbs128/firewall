namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;

/// <summary>
/// Configuration settings for the MaxMind GeoIP database.
/// </summary>
public sealed class GeoIPDatabaseConfig
{
    /// <summary>
    /// Path to a MaxMind GeoIP2 Country database.
    /// </summary>
    // must use init as setter; internal set causes value binding to fail
    public string GeoIPDatabasePath { get; internal set; } = string.Empty;

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is GeoIPDatabaseConfig other && string.Equals(GeoIPDatabasePath, other.GeoIPDatabasePath, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public override int GetHashCode() => GeoIPDatabasePath.GetHashCode();
}

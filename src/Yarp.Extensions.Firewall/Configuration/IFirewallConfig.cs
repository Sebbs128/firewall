using System.Runtime.CompilerServices;

using Microsoft.Extensions.Primitives;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Represents a snapshot of firewall configuration data. These properties may be accessed multiple times and should not be modified.
/// </summary>
public interface IFirewallConfig
{
    private static readonly ConditionalWeakTable<IFirewallConfig, string> _revisionIdsTable = [];

    /// <summary>
    /// A unique identifier for this revision of the configuration.
    /// </summary>
    public string RevisionId => _revisionIdsTable.GetValue(this, static _ => Guid.NewGuid().ToString());

    /// <summary>
    /// Firewall information matching to proxy routes.
    /// </summary>
    // dependent on YARP, matching to the route via the IReverseProxyFeature which allows middleware inside the MapReverseProxy pipeline
    // - this is how the session affinity and load balancing works in Yarp
    public IReadOnlyList<RouteFirewallConfig> RouteFirewalls { get; }

    /// <summary>
    /// Path to a MaxMind GeoIP2 Country database.
    /// </summary>
    public string GeoIPDatabasePath { get; }

    /// <summary>
    /// A notification that triggers when this snapshot expires.
    /// </summary>
    public IChangeToken ChangeToken { get; }
}

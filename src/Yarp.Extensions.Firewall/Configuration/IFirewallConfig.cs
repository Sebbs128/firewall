using Microsoft.Extensions.Primitives;

using System.Runtime.CompilerServices;

namespace Yarp.Extensions.Firewall.Configuration;

public interface IFirewallConfig
{
    private static readonly ConditionalWeakTable<IFirewallConfig, string> _revisionIdsTable = new();

    string RevisionId => _revisionIdsTable.GetValue(this, static _ => Guid.NewGuid().ToString());

    // dependent on YARP, matching to the route via the IReverseProxyFeature which allows middleware inside the MapReverseProxy pipeline
    // - this is how the session affinity and load balancing works in Yarp
    IReadOnlyList<RouteFirewallConfig> RouteFirewalls { get; }

    string GeoIPDatabasePath { get; }

    IChangeToken ChangeToken { get; }
}

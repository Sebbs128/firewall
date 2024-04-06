using System.Diagnostics.CodeAnalysis;

using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Management;

/// <summary>
/// Allows access to the firewall's current set of route firewalls.
/// </summary>
public interface IFirewallStateLookup
{
    /// <summary>
    /// Retrieves a specific route firewall by id, if present.
    /// </summary>
    bool TryGetRouteFirewall(string id, [NotNullWhen(true)] out RouteFirewallModel? firewall);

    /// <summary>
    /// Enumerates all current route firewalls.
    /// This is thread safe but the collection may change mid enumeration if the configuration is reloaded.
    /// </summary>
    /// <returns></returns>
    IEnumerable<RouteFirewallModel> GetRouteFirewalls();
}

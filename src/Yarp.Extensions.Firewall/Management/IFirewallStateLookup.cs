using System.Diagnostics.CodeAnalysis;

using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Management;

public interface IFirewallStateLookup
{
    bool TryGetRouteFirewall(string id, [NotNullWhen(true)] out RouteFirewallModel? firewall);
    IEnumerable<RouteFirewallModel> GetRouteFirewalls();
}

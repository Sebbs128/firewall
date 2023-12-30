using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public interface IEvaluatorBuilder
{
    RouteEvaluator Build(RouteFirewallConfig firewall, RouteConfig? route);
    IReadOnlyList<Exception> Validate(RouteFirewallConfig config);
}
using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Validates and builds firewall rules for a given route firewall.
/// </summary>
public interface IEvaluatorBuilder
{
    /// <summary>
    /// Validates that each rule for the given route firewall is known and has the expected parameters.
    /// All conditions are validated so all errors can be repoted.
    /// </summary>
    public IReadOnlyList<Exception> Validate(RouteFirewallConfig config);

    /// <summary>
    /// Builds the rules for the given route firewall into executable rules.
    /// </summary>
    /// <param name="firewall"></param>
    /// <param name="route"></param>
    /// <returns></returns>
    public RouteEvaluator Build(RouteFirewallConfig firewall, RouteConfig? route);
}

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public class EvaluatorValidationContext
{
    public IList<Exception> Errors { get; } = new List<Exception>();
    public RouteFirewallConfig Firewall { get; init; } = default!;
}
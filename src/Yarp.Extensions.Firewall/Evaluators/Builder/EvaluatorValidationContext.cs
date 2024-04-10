using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// State used when validating condition evaluators for the given route firewall.
/// </summary>
public class EvaluatorValidationContext
{
    /// <summary>
    /// The route firewall these condition evaluators are associated with.
    /// </summary>
    public RouteFirewallConfig Firewall { get; init; } = default!;

    /// <summary>
    /// The accumulated list of validation errors for this route firewall.
    /// Add condition evaluator validation errors here.
    /// </summary>
    public IList<Exception> Errors { get; } = [];
}

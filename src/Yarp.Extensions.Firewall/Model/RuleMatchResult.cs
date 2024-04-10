using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Encapsulates details of the rule that matched a request.
/// </summary>
/// <param name="RuleName">The name of the rule that matched the request.</param>
/// <param name="Action">The action associated with the rule.</param>
public record RuleMatchResult(string RuleName, MatchAction Action)
{
    /// <summary>
    /// A collection encapsulating details about the conditions that matched the request.
    /// </summary>
    public IEnumerable<EvaluatorMatchValue> MatchedValues { get; init; } = [];
}

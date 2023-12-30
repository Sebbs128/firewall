using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Model;

public record RuleMatchResult(string RuleName, MatchAction Action)
{
    public IEnumerable<EvaluatorMatchValue> MatchedValues { get; init; } = new List<EvaluatorMatchValue>();
}

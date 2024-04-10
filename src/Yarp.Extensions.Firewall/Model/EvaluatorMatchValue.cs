namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Encapsulates details of a condition evaluator match.
/// </summary>
/// <param name="MatchVariableName">The name of the request property that matched.</param>
/// <param name="OperatorName">How the condition was matched.</param>
/// <param name="MatchVariableValue">The value that was matched.</param>
public sealed record EvaluatorMatchValue(string MatchVariableName, string OperatorName, string MatchVariableValue);

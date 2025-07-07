using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// The base class for condition evaluators.
/// </summary>
/// <remarks>
/// Creates a new instance.
/// </remarks>
public abstract class ConditionEvaluator(bool negate)
{

    /// <summary>
    /// Invert the result of the condition evaluation.
    /// </summary>
    public bool Negate { get; init; } = negate;

    /// <summary>
    /// Evaluates the captured HTTP request against the condition.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public abstract ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// The base class for condition evaluators for a given operator type.
/// </summary>
/// <typeparam name="TOperator"></typeparam>
/// <remarks>
/// Creates a new instance.
/// </remarks>
public abstract class ConditionEvaluator<TOperator>(TOperator @operator, bool negate) : ConditionEvaluator(negate) where TOperator : Enum
{

    /// <summary>
    /// The type of comparison to perform.
    /// </summary>
    public TOperator Operator { get; init; } = @operator;
}

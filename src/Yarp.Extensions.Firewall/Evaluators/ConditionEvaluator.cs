using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// The base class for condition evaluators.
/// </summary>
public abstract class ConditionEvaluator
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    protected ConditionEvaluator(bool negate)
    {
        Negate = negate;
    }

    /// <summary>
    /// Invert the result of the condition evaluation.
    /// </summary>
    public bool Negate { get; init; }

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
public abstract class ConditionEvaluator<TOperator> : ConditionEvaluator where TOperator : Enum
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    protected ConditionEvaluator(TOperator @operator, bool negate) : base(negate)
    {
        Operator = @operator;
    }

    /// <summary>
    /// The type of comparison to perform.
    /// </summary>
    public TOperator Operator { get; init; }
}

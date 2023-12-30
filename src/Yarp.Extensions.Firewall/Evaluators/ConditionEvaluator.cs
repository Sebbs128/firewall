using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

public abstract class ConditionEvaluator
{
    protected ConditionEvaluator(bool negate)
    {
        Negate = negate;
    }

    public bool Negate { get; init; }

    public abstract ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default);
}

public abstract class ConditionEvaluator<TOperator> : ConditionEvaluator where TOperator : Enum
{
    protected ConditionEvaluator(TOperator @operator, bool negate) : base(negate)
    {
        Operator = @operator;
    }

    public TOperator Operator { get; init; }
}

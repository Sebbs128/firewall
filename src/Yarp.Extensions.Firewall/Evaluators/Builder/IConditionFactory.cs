using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public interface IConditionFactory
{
    bool Validate(EvaluatorValidationContext context, MatchCondition condition);
    bool Build(ConditionBuilderContext context, MatchCondition condition);
}
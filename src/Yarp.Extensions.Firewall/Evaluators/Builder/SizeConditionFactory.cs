using System.Linq;
using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

internal sealed class SizeConditionFactory : IConditionFactory
{
    public bool Validate(EvaluatorValidationContext context, MatchCondition condition)
    {
        if (condition is SizeMatchCondition sizeCondition)
        {
            switch (sizeCondition.MatchVariable)
            {
                case MatchVariable.Cookie:
                case MatchVariable.PostArgs:
                case MatchVariable.RequestHeader:
                    ValidateConditionWithSelector(context, sizeCondition);
                    break;
                case MatchVariable.QueryParam:
                case MatchVariable.RequestBody:
                case MatchVariable.RequestMethod:
                case MatchVariable.RequestPath:
                    ValidateCondition(context, sizeCondition);
                    break;
                default:
                    context.Errors.Add(new ArgumentException($"Unexpected match variable for SizeMatchCondition: {sizeCondition.MatchVariable}."));
                    break;
            }

            return true;
        }

        return false;
    }

    public bool Build(ConditionBuilderContext context, MatchCondition condition)
    {
        if (condition is SizeMatchCondition sizeCondition)
        {
            // TODO: check sizeCondition contains all expected parameters
            // although Validate() should be checking all parameters are there, this will enforce eg. a selector is provided when expected
            _ = sizeCondition.MatchVariable switch
            {
                MatchVariable.Cookie => context.AddRequestCookieSizeEvaluator(sizeCondition),
                MatchVariable.PostArgs => context.AddRequestPostArgsSizeEvaluator(sizeCondition),
                MatchVariable.QueryParam => context.AddRequestQueryStringSizeEvaluator(sizeCondition),
                MatchVariable.RequestBody => context.AddRequestBodySizeEvaluator(sizeCondition),
                MatchVariable.RequestHeader => context.AddRequestHeaderSizeEvaluator(sizeCondition),
                MatchVariable.RequestMethod => context.AddRequestMethodSizeEvaluator(sizeCondition),
                MatchVariable.RequestPath => context.AddRequestPathSizeEvaluator(sizeCondition),
                _ => throw new ArgumentException($"Unexpected match variable for SizeMatchCondition: {sizeCondition.MatchVariable}.")
            };

            return true;
        }

        return false;
    }

    private static void ValidateConditionWithSelector(EvaluatorValidationContext context, SizeMatchCondition condition)
    {
        if (string.IsNullOrWhiteSpace(condition.Selector))
            context.Errors.Add(new ArgumentException("Missing selector value for SizeMatchCondition"));

        ValidateCondition(context, condition);
    }

    private static void ValidateCondition(EvaluatorValidationContext context, SizeMatchCondition condition)
    {
        switch (condition.Operator)
        {
            case NumberOperator.LessThan:
            case NumberOperator.GreaterThan:
            case NumberOperator.LessThanOrEqual:
            case NumberOperator.GreaterThanOrEqual:
                break;
            default:
                context.Errors.Add(new ArgumentException($"Unexpected match operator for SizeMatchCondition: {condition.Operator}"));
                break;
        }
        ConditionHelper.TryCheckTransforms(context, condition.Transforms);
    }
}

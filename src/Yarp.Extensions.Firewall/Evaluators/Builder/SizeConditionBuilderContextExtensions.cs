using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class SizeConditionBuilderContextExtensions
{
    public static ConditionBuilderContext AddRequestCookieSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestCookieSizeEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestPostArgsSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestPostArgsSizeEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestQueryStringSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestQueryParamSizeEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestBodySizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodySizeEvaluator evaluator = new(
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodySizeEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestHeaderSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestHeaderSizeEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestMethodSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestMethodSizeEvaluator evaluator = new(
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddRequestPathSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
    {
        RequestPathSizeEvaluator evaluator = new(
            matchCondition.Operator,
            matchCondition.MatchValue,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }
}

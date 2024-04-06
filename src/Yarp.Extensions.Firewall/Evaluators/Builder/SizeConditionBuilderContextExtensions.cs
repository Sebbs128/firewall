using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Extensions for adding size/length evaluators.
/// </summary>
public static class SizeConditionBuilderContextExtensions
{
    /// <summary>
    /// Adds an evaluator for cookie length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Adds an evaluator for POST parameter length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Adds an evaluator for query parameter length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestQueryParamSizeEvaluator(this ConditionBuilderContext context, SizeMatchCondition matchCondition)
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

    /// <summary>
    /// Adds an evaluator for request body length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Adds an evaluator for request header length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Adds an evaluator for request method length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
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

    /// <summary>
    /// Adds an evaluator for URL path length.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
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

using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Extensions for adding string evaluators
/// </summary>
public static class StringConditionBuilderContextExtensions
{
    /// <summary>
    /// Adds an evaluator for cookie values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestCookieStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestCookieStringEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for cookie regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestCookieRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestCookieRegexEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for POST parameter values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestPostArgsStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestPostArgsStringEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for POST parameter regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestPostArgsRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestPostArgsRegexEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for query parameter values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestQueryParamStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestQueryParamStringEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for query parameter regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestQueryParamRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestQueryParamRegexEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body having any content.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyStringAnyEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringAnyEvaluator evaluator = new(
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringAnyEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body equalling values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyStringEqualsEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringEqualsEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringEqualsEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body containing values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyStringContainsEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringContainsEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringContainsEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body starting with values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyStringStartsWithEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringStartsWithEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringStartsWithEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body ending with values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyStringEndsWithEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringEndsWithEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringEndsWithEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request body regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="loggerFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestBodyRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyRegexEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyRegexEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request header values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestHeaderStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestHeaderStringEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request header regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestHeaderRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestHeaderRegexEvaluator evaluator = new(
            matchCondition.Selector,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request method values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestMethodStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestMethodStringEvaluator evaluator = new(
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for request method regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestMethodRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestMethodRegexEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for URL path values.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestPathStringEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestPathStringEvaluator evaluator = new(
            matchCondition.Operator,
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for URL path regular expression patterns.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRequestPathRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestPathRegexEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }
}

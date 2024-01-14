using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class StringConditionBuilderContextExtensions
{
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

    public static ConditionBuilderContext AddRequestBodyStringAnyEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition, ILoggerFactory loggerFactory)
    {
        RequestBodyStringAnyEvaluator evaluator = new(
            matchCondition.Negate,
            matchCondition.Transforms,
            loggerFactory.CreateLogger<RequestBodyStringAnyEvaluator>());
        context.RuleConditions.Add(evaluator);
        return context;
    }

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

    public static ConditionBuilderContext AddRequestMethodRegexEvaluator(this ConditionBuilderContext context, StringMatchCondition matchCondition)
    {
        RequestMethodRegexEvaluator evaluator = new(
            matchCondition.MatchValues,
            matchCondition.Negate,
            matchCondition.Transforms);
        context.RuleConditions.Add(evaluator);
        return context;
    }

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

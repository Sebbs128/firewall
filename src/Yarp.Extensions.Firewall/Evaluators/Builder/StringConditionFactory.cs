using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

internal sealed class StringConditionFactory(ILoggerFactory loggerFactory) : IConditionFactory
{
    private readonly ILoggerFactory _loggerFactory = loggerFactory;

    public bool Validate(EvaluatorValidationContext context, MatchCondition condition)
    {
        if (condition is StringMatchCondition stringCondition)
        {
            switch (stringCondition.MatchVariable)
            {
                case MatchVariable.Cookie:
                case MatchVariable.PostArgs:
                case MatchVariable.RequestHeader:
                case MatchVariable.QueryParam:
                    ValidateConditionWithSelector(context, stringCondition);
                    break;
                case MatchVariable.RequestBody:
                case MatchVariable.RequestMethod:
                case MatchVariable.RequestPath:
                    ValidateCondition(context, stringCondition);
                    break;
                default:
                    context.Errors.Add(new ArgumentException($"Unexpected match variable for StringMatchCondition: {stringCondition.MatchVariable}"));
                    break;
            }

            return true;
        }

        return false;
    }

    public bool Build(ConditionBuilderContext context, MatchCondition condition)
    {
        if (condition is StringMatchCondition stringCondition)
        {
            _ = stringCondition switch
            {
                // Regex evaluators
                { MatchVariable: MatchVariable.Cookie, Operator: StringOperator.Regex } => context.AddRequestCookieRegexEvaluator(stringCondition),
                { MatchVariable: MatchVariable.PostArgs, Operator: StringOperator.Regex } => context.AddRequestPostArgsRegexEvaluator(stringCondition),
                { MatchVariable: MatchVariable.QueryParam, Operator: StringOperator.Regex } => context.AddRequestQueryParamRegexEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestHeader, Operator: StringOperator.Regex } => context.AddRequestHeaderRegexEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestMethod, Operator: StringOperator.Regex } => context.AddRequestMethodRegexEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestPath, Operator: StringOperator.Regex } => context.AddRequestPathRegexEvaluator(stringCondition),

                { MatchVariable: MatchVariable.Cookie } => context.AddRequestCookieStringEvaluator(stringCondition),
                { MatchVariable: MatchVariable.PostArgs } s => context.AddRequestPostArgsStringEvaluator(stringCondition),
                { MatchVariable: MatchVariable.QueryParam } g => context.AddRequestQueryParamStringEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestHeader } r => context.AddRequestHeaderStringEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestMethod } d => context.AddRequestMethodStringEvaluator(stringCondition),
                { MatchVariable: MatchVariable.RequestPath } th => context.AddRequestPathStringEvaluator(stringCondition),

                // Request Body evaluators
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.Regex } => context.AddRequestBodyRegexEvaluator(stringCondition, _loggerFactory),
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.Any } y => context.AddRequestBodyStringAnyEvaluator(stringCondition, _loggerFactory),
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.Equals } => context.AddRequestBodyStringEqualsEvaluator(stringCondition, _loggerFactory),
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.Contains } => context.AddRequestBodyStringContainsEvaluator(stringCondition, _loggerFactory),
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.StartsWith } => context.AddRequestBodyStringStartsWithEvaluator(stringCondition, _loggerFactory),
                { MatchVariable: MatchVariable.RequestBody, Operator: StringOperator.EndsWith } => context.AddRequestBodyStringEndsWithEvaluator(stringCondition, _loggerFactory),

                _ => throw new ArgumentException($"Unexpected match variable for {nameof(StringMatchCondition)}: {stringCondition.MatchVariable}.")
            };

            return true;
        }

        return false;
    }

    private static void ValidateConditionWithSelector(EvaluatorValidationContext context, StringMatchCondition condition)
    {
        if (string.IsNullOrWhiteSpace(condition.Selector))
        {
            context.Errors.Add(new ArgumentException("Missing selector value for SizeMatchCondition"));
        }

        ValidateCondition(context, condition);
    }

    private static void ValidateCondition(EvaluatorValidationContext context, StringMatchCondition condition)
    {
        switch (condition.Operator)
        {
            case StringOperator.Any:
                break;
            case StringOperator.Contains:
            case StringOperator.Equals:
            case StringOperator.Regex:
            case StringOperator.StartsWith:
            case StringOperator.EndsWith:
                if (condition.MatchValues.Count == 0)
                {
                    context.Errors.Add(new ArgumentException("Missing match values for StringMatchCondition"));
                }

                break;
            default:
                context.Errors.Add(new ArgumentException($"Unexpected match operator for StringMatchCondition: {condition.Operator}"));
                break;
        }
        ConditionHelper.TryCheckTransforms(context, condition.Transforms);
    }
}

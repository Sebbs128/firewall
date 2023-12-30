using System.Data;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

internal sealed class EvaluatorBuilder : IEvaluatorBuilder
{
    private readonly IEnumerable<IConditionFactory> _factories;

    public EvaluatorBuilder(IEnumerable<IConditionFactory> factories)
    {
        _factories = factories;
    }

    public IReadOnlyList<Exception> Validate(RouteFirewallConfig firewall)
    {
        var context = new EvaluatorValidationContext()
        {
            Firewall = firewall
        };

        var rawRules = firewall?.Rules;
        if (rawRules?.Count > 0)
        {
            foreach (var rawRule in rawRules)
            {
                foreach (var rawCondition in rawRule.Conditions)
                {
                    var handled = false;
                    foreach (var factory in _factories)
                    {
                        if (factory.Validate(context, rawCondition))
                        {
                            handled = true;
                            break;
                        }
                    }

                    if (!handled)
                    {
                        context.Errors.Add(new ArgumentException($"Unknown condition: {rawCondition.MatchType}"));
                    }
                }
            }
        }

        return (IReadOnlyList<Exception>)context.Errors;
    }

    public RouteEvaluator Build(RouteFirewallConfig firewall, RouteConfig? route)
    {

        var ruleContext = new RuleEvaluatorBuilderContext
        {
            Firewall = firewall,
            Route = route,
        };

        var rawRules = firewall?.Rules;
        if (rawRules?.Count > 0)
        {
            foreach (var rawRule in rawRules)
            {
                var context = new ConditionBuilderContext
                {
                    RuleName = rawRule.RuleName,
                    Priority = rawRule.Priority,
                    Action = rawRule.Action,
                };

                foreach (var rawCondition in rawRule.Conditions)
                {
                    var handled = false;
                    foreach (var factory in _factories)
                    {
                        if (factory.Build(context, rawCondition))
                        {
                            handled = true;
                            break;
                        }
                    }

                    if (!handled)
                    {
                        throw new ArgumentException($"Unknown condition: {string.Join("';'", rawCondition.MatchType)}");
                    }
                }

                ruleContext.ConditionBuilders.Add(context);
            }
        }

        return CreateRouteEvaluator(ruleContext);
    }

    internal static RouteEvaluator CreateRouteEvaluator(RuleEvaluatorBuilderContext ruleContext)
    {
        var ruleEvaluators = new List<RuleEvaluator>();
        foreach (var rule in ruleContext.ConditionBuilders.OrderBy(r => r.Priority))
        {
            var evaluator = new RuleEvaluator(
                rule.RuleName,
                rule.Priority,
                rule.Action,
                rule.RuleConditions);

            ruleEvaluators.Add(evaluator);
        }

        return new RouteEvaluator(
            ruleContext.Route!.RouteId,
            ruleContext.Firewall.Enabled,
            ruleContext.Firewall.Mode,
            ruleContext.Firewall.RedirectUri,
            ruleContext.Firewall.BlockedStatusCode,
            ruleEvaluators);
    }
}

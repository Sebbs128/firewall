using System.Buffers;
using System.Net;

using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RouteEvaluator
{
    public RouteEvaluator(string routeId, bool enabled, FirewallMode mode, string? redirectUri, HttpStatusCode blockedStatusCode, IList<RuleEvaluator> ruleEvaluators)
    {
        ArgumentNullException.ThrowIfNull(ruleEvaluators);

        RouteId = routeId;
        Enabled = enabled;
        Mode = mode;
        RedirectUri = redirectUri;
        BlockedStatusCode = blockedStatusCode;
        RuleEvaluators = ruleEvaluators.ToArray();
    }

    public string RouteId { get; }
    public bool Enabled { get; }
    public FirewallMode Mode { get; }
    public string? RedirectUri { get; }
    public HttpStatusCode BlockedStatusCode { get; }
    public RuleEvaluator[] RuleEvaluators { get; }

    public async Task<RuleMatchResult?> EvaluateRequestAsync(HttpContext context, CancellationToken cancellationToken)
    {
        foreach (var evaluator in RuleEvaluators)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            EvaluationContext evaluationContext = new(context);

            var isMatch = await evaluator.EvaluateRequestAsync(evaluationContext, cancellationToken);

            if (isMatch)
            {
                return new RuleMatchResult(evaluator.RuleName, evaluator.Action)
                {
                    MatchedValues = evaluationContext.MatchedValues
                };
            }
        }

        return null;
    }

    private static class Log
    {
        
    }
}

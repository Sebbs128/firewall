using System.Buffers;
using System.Net;

using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// The firewall for a proxy route.
/// Evaluates a collection of rules for a route.
/// </summary>
public class RouteEvaluator
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
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

    /// <summary>
    /// The name of the route.
    /// </summary>
    public string RouteId { get; }

    /// <summary>
    /// Whether requests should be evaluated with this rule collection or not.
    /// </summary>
    public bool Enabled { get; }

    /// <summary>
    /// Operating mode of the firewall.
    /// </summary>
    public FirewallMode Mode { get; }

    /// <summary>
    /// Location clients should be redirected to for Redirect results.
    /// </summary>
    public string? RedirectUri { get; }

    /// <summary>
    /// HTTP status code returned to the client for Block results.
    /// </summary>
    public HttpStatusCode BlockedStatusCode { get; }

    /// <summary>
    /// The collection of rules comprising the firewall.
    /// </summary>
    public RuleEvaluator[] RuleEvaluators { get; }

    /// <summary>
    /// Evaluates a HTTP request against the collection of rules.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> containing the request.</param>
    /// <param name="cancellationToken">Indicates that the request is being cancelled.</param>
    /// <returns>Details of the rule and condtions if a match was found, otherwise null.</returns>
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

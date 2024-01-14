using System.Diagnostics;
using System.Net;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators;
using Yarp.Extensions.Firewall.Management;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall;

internal sealed class CustomRuleMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IFirewallStateLookup _firewallStateLookup;
    private readonly ILogger<CustomRuleMiddleware> _logger;

    public CustomRuleMiddleware(RequestDelegate next, IFirewallStateLookup firewallStateLookup, ILogger<CustomRuleMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(next, nameof(next));
        ArgumentNullException.ThrowIfNull(logger, nameof(logger));

        _next = next;
        _firewallStateLookup = firewallStateLookup;
        _logger = logger;
    }

    public Task Invoke(HttpContext context)
    {
        var proxyFeature = context.GetReverseProxyFeature();

        var routeId = proxyFeature.Route.Config.RouteId;

        if (routeId is not null && _firewallStateLookup.TryGetRouteFirewall(routeId, out var routeFirewall))
        {
            return EvaluateFirewallRules(context, routeFirewall.Evaluator);
        }

        return _next(context);
    }

    internal async Task EvaluateFirewallRules(HttpContext context, RouteEvaluator routeEvaluator)
    {
        if (routeEvaluator.Enabled)
        {
            var result = await routeEvaluator.EvaluateRequestAsync(context, context.RequestAborted);

            if (result is not null)
            {
                // values to be logged: mode, rule name, action, match details(name, type, value), request url, client ip address, client port, socket ip address, trace id
                // see for example https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-monitor?pivots=front-door-standard-premium#waf-logs
                using var activity = Observability.FirewallActivitySource.CreateActivity("firewall.evaluate", ActivityKind.Server);
                if (activity is not null)
                {
                    context.SetFirewallActivity(activity);
                    activity.AddTag("firewall.route_id", routeEvaluator.RouteId);
                    activity.AddTag("firewall.mode", routeEvaluator.Mode);
                    activity.AddTag("firewall.rule_name", result.RuleName);
                    activity.AddTag("firewall.action", result.Action);
                    activity.AddTag("firewall.details", result.MatchedValues);
                }

                bool responseStatusSet = false;

                switch (result.Action)
                {
                    case MatchAction.Block:
                        if (routeEvaluator.Mode == FirewallMode.Prevention)
                        {
                            context.Response.StatusCode = (int)routeEvaluator.BlockedStatusCode;
                            responseStatusSet = true;
                        }
                        goto case MatchAction.Log;
                    case MatchAction.Redirect:
                        if (routeEvaluator.Mode == FirewallMode.Prevention)
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.Redirect;
                            context.Response.Headers.Location = routeEvaluator.RedirectUri;
                            responseStatusSet = true;
                        }
                        goto case MatchAction.Log;
                    case MatchAction.Log:
                        Log.ActionTaken(_logger, result.Action, routeEvaluator.RouteId, context.Request.GetEncodedUrl());
                        break;
                    case MatchAction.Allow:
                        break;
                    default:
                        throw new NotImplementedException($"Unexpected firewall action for route {routeEvaluator.RouteId}: {result.Action}");
                }

                if (responseStatusSet)
                    return;
            }
        }

        await _next(context);
    }

    private static class Log
    {
        private static readonly Action<ILogger, MatchAction, string, string, Exception?> _actionTaken = LoggerMessage.Define<MatchAction, string, string>(
            LogLevel.Information,
            EventIds.ActionTaken,
            "Firewall took action '{action}' on Route '{routeId}' URL {uri}");

        public static void ActionTaken(ILogger logger, MatchAction action, string routeId, string uri)
        {
            _actionTaken(logger, action, routeId, uri, null);
        }
    }
}

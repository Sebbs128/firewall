using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

using System.Diagnostics;

namespace Yarp.Extensions.Firewall.Utilities;

internal static class Observability
{
    public static readonly ActivitySource FirewallActivitySource = new ActivitySource("Yarp.Extensions.Firewall");

    public static Activity? GetFirewallActivity(this HttpContext context)
    {
        return context.Features[typeof(FirewallActivity)] as Activity;
    }

    public static void SetFirewallActivity(this HttpContext context, Activity? activity)
    {
        if (activity is not null)
        {
            activity.SetTag("firewall.host", context.Request.Host);
            activity.SetTag("firewall.request_uri", context.Request.GetEncodedUrl());
            activity.SetTag("firewall.socket_ip", context.Connection.RemoteIpAddress);
            activity.SetTag("firewall.client_ip", context.GetRemoteIPAddress());
            activity.SetTag("firewall.client_port", context.Connection.RemotePort);
            activity.SetTag("firewall.tracking_ref", context.TraceIdentifier);

            context.Features[typeof(FirewallActivity)] = activity;
        }
    }

    public static void AddError(this Activity activity, string message, string description)
    {
        if (activity is not null)
        {
            var tagsCollection = new ActivityTagsCollection
            {
                { "error", message },
                { "description", description }
            };

            activity.AddEvent(new ActivityEvent("Error", default, tagsCollection));
        }
    }

    private class FirewallActivity
    {
    }
}

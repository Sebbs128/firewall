using System.Net;

using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Utilities;

public static class HttpContextExtensions
{
    public static IPAddress? GetRemoteIPAddress(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var header))
        {
            foreach (var item in header)
            {
                if (IPAddress.TryParse(item, out var value))
                    return value;
            }
        }
        return context.Connection.RemoteIpAddress;
    }
}

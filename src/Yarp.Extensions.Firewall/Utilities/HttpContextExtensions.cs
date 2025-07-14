using System.Net;

using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Utilities;

/// <summary>
/// Extension methods for fetching request information from the current HttpContext.
/// </summary>
public static class HttpContextExtensions
{
    /// <summary>
    /// Retrieves the remote <see cref="IPAddress"/> of the client associated with the current request.
    /// This will be the first valid 'X-Forwarded-For' header if any, falling back to the socket address.
    /// </summary>
    public static IPAddress? GetRemoteIPAddress(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var header))
        {
            foreach (var item in header)
            {
                if (IPAddress.TryParse(item, out var value))
                {
                    return value;
                }
            }
        }
        return context.Connection.RemoteIpAddress;
    }
}

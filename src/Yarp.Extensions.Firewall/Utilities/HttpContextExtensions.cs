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
    /// This will be the first valid 'for' directive in a Forwarded header, if any,
    /// first falling back to the first valid 'X-Forwarded-For' header, if any,
    /// then falling back to the socket address.
    /// </summary>
    public static IPAddress? GetRemoteIPAddress(this HttpContext context)
    {
        return context.GetRemoteIPAddressFromForwardedHeader()
            ?? context.GetRemoteIPAddressFromXForwardedForHeader()
            ?? context.Connection.RemoteIpAddress;
    }

    /// <summary>
    /// Retrieves the remote <see cref="IPAddress"/> of the client associated with the current request based on the Forwarded header <c>for</c> directive.
    /// </summary>
    /// <param name="context"></param>
    /// <returns>
    /// The first valid IP address found in the header's <c>for</c> directive, otherwise <c>null</c>.
    /// </returns>
    public static IPAddress? GetRemoteIPAddressFromForwardedHeader(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("Forwarded", out var header))
        {
            foreach (var item in header)
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }

                // directives are ';' separated, but when there is multiple values for the same directive, they are ',' separated
                var directives = item.Split([';', ','], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                foreach (var directive in directives)
                {
                    if (directive.StartsWith("for=", StringComparison.OrdinalIgnoreCase))
                    {
                        if (TryParseForDirective(directive, out var address))
                        {
                            return address;
                        }
                    }
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Retrieves all remote <see cref="IPAddress"/>es of the client associated with the current request based on the Forwarded header <c>for</c> directive.
    /// </summary>
    /// <param name="context"></param>
    /// <returns>
    /// An enumerable collection of valid IP addresses found in the X-Forwarded-For header.
    /// </returns>
    public static IEnumerable<IPAddress> GetRemoteIPAddressesFromForwardedHeader(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("Forwarded", out var header))
        {
            foreach (var item in header)
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }
                // directives are ';' separated, but when there is multiple values for the same directive, they are ',' separated
                var directives = item.Split([';', ','], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                foreach (var directive in directives)
                {
                    if (TryParseForDirective(directive, out var address) && address != null)
                    {
                        yield return address;
                    }
                }
            }
        }
    }

    private static bool TryParseForDirective(string directive, out IPAddress? address)
    {
        address = null;
        if (directive.StartsWith("for=", StringComparison.OrdinalIgnoreCase))
        {
            var span = directive.AsSpan(4).Trim('"');
            // Forwarded allows for an optional port number after the IP address
            // IPAddress.TryParse() will handle this fine for an IPv6 address formatted according to RFC 7239
            // but not for IPv4 addresses with a port number
            if (span is not ['[', ..])
            {
                var lastColonIndex = span.LastIndexOf(':');
                if (lastColonIndex >= 0)
                {
                    span = span[..lastColonIndex];
                }
            }
            return IPAddress.TryParse(span, out address);
        }
        return false;
    }

    /// <summary>
    /// Retrieves the remote <see cref="IPAddress"/> of the client associated with the current request based on the X-Forwarded-For header.
    /// </summary>
    /// <param name="context"></param>
    /// <returns>
    /// The first valid IP address found, otherwise <c>null</c>.
    /// </returns>
    public static IPAddress? GetRemoteIPAddressFromXForwardedForHeader(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var header))
        {
            foreach (var item in header)
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }

                var values = item.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                foreach (var value in values)
                {
                    if (IPAddress.TryParse(value, out var ipAddress))
                    {
                        return ipAddress;
                    }
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Retrieves all remote <see cref="IPAddress"/>es of the client associated with the current request based on the X-Forwarded-For header.
    /// </summary>
    /// <param name="context"></param>
    /// <returns>
    /// An enumerable collection of valid IP addresses found in the X-Forwarded-For header.
    /// </returns>
    public static IEnumerable<IPAddress> GetRemoteIPAddressesFromXForwardedForHeader(this HttpContext context)
    {
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var header))
        {
            foreach (var item in header)
            {
                if (string.IsNullOrWhiteSpace(item))
                {
                    continue;
                }

                var values = item.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                foreach (var value in values)
                {
                    if (IPAddress.TryParse(value, out var ipAddress))
                    {
                        yield return ipAddress;
                    }
                }
            }
        }
    }
}

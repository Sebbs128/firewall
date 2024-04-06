using System.Net;
using System.Net.Sockets;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Helper methods for validation and building IP address conditions.
/// </summary>
public static class IPAddressHelpers
{
    private const StringSplitOptions SplitOptions = StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries;

    /// <summary>
    /// Checks if the given <see cref="string"/> is a comma-separated list of CIDR ranges.
    /// </summary>
    /// <param name="context">The context to add any generated errors to.</param>
    /// <param name="rawIpAddressRanges"></param>
    public static void TryParseCidrRanges(EvaluatorValidationContext context, string rawIpAddressRanges)
    {
        var cidrStrings = rawIpAddressRanges.Split(',', SplitOptions);

        if (cidrStrings.Length == 0)
        {
            context.Errors.Add(new InvalidOperationException("The condition contains no values"));
        }

        foreach (var cidrString in cidrStrings)
        {
            var components = cidrString.Split('/', SplitOptions);
            if (components.Length != 2)
            {
                context.Errors.Add(new InvalidOperationException($"The value does not contain a CIDR range: {cidrString}"));
            }
            else
            {
                if (!IPAddress.TryParse(components[0], out var ipAddress))
                {
                    context.Errors.Add(new InvalidOperationException($"The value does not contain a valid IP address: {components[0]}"));
                }

                var (min, max) = ipAddress?.AddressFamily switch
                {
                    AddressFamily.InterNetwork => (Min: 0, Max: 32),
                    AddressFamily.InterNetworkV6 => (Min: 0, Max: 128),
                    _ => (Min: 0, Max: 0) // using Max of 0 to ensure the check on the range will always fail if ipAddress isn't v4 or v6
                };

                if (!int.TryParse(components[1], out var mask) || mask < min || mask > max)
                {
                    context.Errors.Add(new InvalidOperationException($"The value does not contain a valid CIDR mask: {components[1]}"));
                }
            }
        }
    }

    /// <summary>
    /// Converts a comma-separated list of CIDR <see cref="string"/>s to a collection of <see cref="IPNetwork"/>s.
    /// </summary>
    /// <remarks>
    /// The exact type of IPNetwork differs depending on the version of .NET:
    /// On .NET 8 and above, IPNetwork is a System.Net.IPNetwork (which was introduced in .NET 8).
    /// On .NET 6 and 7, IPNetwork is a Microsoft.AspNetCore.HttpOverrides.IPNetwork.
    /// System.Net.IPNetwork has a Parse() method lacking in MS.AspNetCore..IPNetwork, and also has additional validity checks on the given mask and base address.
    /// </remarks>
    /// <param name="rawIpAddressRanges">A comma-separated list of CIDR <see cref="string"/>s</param>
    /// <returns>A collection of <see cref="IPNetwork"/>s.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static IReadOnlyList<IPNetwork> ParseCidrRanges(string rawIpAddressRanges)
    {
        var ipAddressRanges = new List<IPNetwork>();
        var cidrStrings = rawIpAddressRanges.Split(',', SplitOptions);

        if (cidrStrings.Length == 0)
        {
            throw new InvalidOperationException("The condition contains no values");
        }

        foreach (var cidrString in cidrStrings)
        {
#if NET8_0_OR_GREATER
            // Allow System.Net.IPNetwork's Parse() method to handle all the parsing, which additionally checks if the mask is valid for the base address
            // It's a lot stricter than the Microsoft.AspNetCore.HttpOverrides.IPNetwork class, which doesn't check if the mask overlaps with the base address's bytes
            var ipRange = IPNetwork.Parse(cidrString);
            ipAddressRanges.Add(ipRange);
#else
            var components = cidrString.Split('/', SplitOptions);
            if (components.Length != 2)
            {
                throw new InvalidOperationException($"The value does not contain a CIDR range: {cidrString}");
            }
            else
            {
                if (!IPAddress.TryParse(components[0], out var ipAddress))
                {
                    throw new InvalidOperationException($"The value does not contain a valid IP address: {components[0]}");
                }

                var (min, max) = ipAddress!.AddressFamily switch
                {
                    AddressFamily.InterNetwork => (Min: 0, Max: 32),
                    AddressFamily.InterNetworkV6 => (Min: 0, Max: 128),
                    _ => (Min: 0, Max: 0) // using Max of 0 to ensure the check on the range will always fail if ipAddress isn't v4 or v6
                };

                if (!int.TryParse(components[1], out var mask) || mask < min || mask > max)
                {
                    throw new InvalidOperationException($"The value does not contain a valid CIDR mask: {components[1]}");
                }

                ipAddressRanges.Add(new IPNetwork(ipAddress, mask));
            }
#endif
        }

        return ipAddressRanges;
    }

    /// <summary>
    /// Checks if the given <see cref="string"/> is a comma-separated list of IP addresses.
    /// </summary>
    /// <param name="context">The context to add any generated errors to.</param>
    /// <param name="rawIpAddresses"></param>
    public static void TryParseIpAddresses(EvaluatorValidationContext context, string rawIpAddresses)
    {
        var ipAddressStrings = rawIpAddresses.Split(',', SplitOptions);

        if (ipAddressStrings.Length == 0)
        {
            context.Errors.Add(new InvalidOperationException("The condition contains no values"));
        }

        foreach (var ipAddressString in ipAddressStrings)
        {
            if (!IPAddress.TryParse(ipAddressString, out var ipAddress))
            {
                context.Errors.Add(new InvalidOperationException($"The value does not contain a valid IP address: {ipAddressString}"));
            }
            else if (ipAddress.AddressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            {
                context.Errors.Add(new InvalidOperationException($"The value does not contain a valid IPv4 or IPv6 address: {ipAddressString}"));
            }
        }
    }

    /// <summary>
    /// Converts a comma-separated list of IP address <see cref="string"/>s to a collection of System.Net.<see cref="IPAddress"/>es.
    /// </summary>
    /// <exception cref="InvalidOperationException"></exception>
    public static IReadOnlyList<IPAddress> ParseIpAddresses(string rawIpAddresses)
    {
        var ipAddresses = new List<IPAddress>();

        var ipAddressStrings = rawIpAddresses.Split(',', SplitOptions);

        if (ipAddressStrings.Length == 0)
        {
            throw new InvalidOperationException("The condition contains no values");
        }

        foreach (var ipAddressString in ipAddressStrings)
        {
            if (!IPAddress.TryParse(ipAddressString, out var ipAddress))
            {
                throw new InvalidOperationException($"The value does not contain a valid IP address: {ipAddressString}");
            }
            if (ipAddress.AddressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            {
                throw new InvalidOperationException($"The value does not contain a valid IPv4 or IPv6 address: {ipAddressString}");
            }
            ipAddresses.Add(ipAddress);
        }

        return ipAddresses;
    }
}

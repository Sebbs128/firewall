using System.Net;
using System.Net.Sockets;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class IPAddressHelpers
{
    private const StringSplitOptions SplitOptions = StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries;

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
            else if (ipAddress.AddressFamily != AddressFamily.InterNetwork && ipAddress.AddressFamily != AddressFamily.InterNetworkV6)
            {
                context.Errors.Add(new InvalidOperationException($"The value does not contain a valid IPv4 or IPv6 address: {ipAddressString}"));
            }
        }
    }

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
            if (ipAddress.AddressFamily != AddressFamily.InterNetwork && ipAddress.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new InvalidOperationException($"The value does not contain a valid IPv4 or IPv6 address: {ipAddressString}");
            }
            ipAddresses.Add(ipAddress);
        }

        return ipAddresses;
    }
}

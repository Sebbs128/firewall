#if !NET8_0_OR_GREATER
using System.Net;

namespace Yarp.Extensions.Firewall.Utilities;

/// <summary>
/// Adapter around <see cref="Microsoft.AspNetCore.HttpOverrides.IPNetwork"/>
/// to present the same API shape as .NET 8's System.Net.IPNetwork in .NET 6 and 7 builds of the library.
/// </summary>
/// <remarks>
/// Creates a new instance.
/// </remarks>
/// <param name="prefix"></param>
/// <param name="prefixLength"></param>
public class IPNetworkWrapper(IPAddress prefix, int prefixLength)
    : Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, prefixLength)
{

    /// <summary>
    /// Gets the <see cref="IPAddress"/> that represents the prefix of the network.
    /// </summary>
    public IPAddress BaseAddress => Prefix;

    /// <summary>
    /// Converts the instance to a string containing the <see cref="IPNetwork"/>'s CIDR notation.
    /// </summary>
    /// <returns>The <see cref="string"/> containing the <see cref="IPNetwork"/>'s CIDR notation.</returns>
    public override string ToString() => $"{BaseAddress}/{PrefixLength}";
}
#endif

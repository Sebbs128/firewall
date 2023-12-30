#if !NET8_0_OR_GREATER
using System.Net;

namespace Yarp.Extensions.Firewall.Utilities;

public class IPNetworkWrapper : Microsoft.AspNetCore.HttpOverrides.IPNetwork
{
    public IPNetworkWrapper(IPAddress prefix, int prefixLength) : base(prefix, prefixLength)
    {
    }

    public IPAddress BaseAddress => Prefix;

    public override string ToString() => $"{BaseAddress}/{PrefixLength}";
}
#endif

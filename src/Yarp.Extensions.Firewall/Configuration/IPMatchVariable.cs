using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// HTTP request properties to source IP addresses from
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IPMatchVariable
{
    /// <summary>
    /// Apparent remote address
    /// </summary>
    RemoteAddress,
    /// <summary>
    /// Physical socket remote address
    /// </summary>
    SocketAddress
}

using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IPMatchVariable
{
    RemoteAddress,
    SocketAddress
}

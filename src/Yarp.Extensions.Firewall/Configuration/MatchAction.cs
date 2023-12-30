using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MatchAction
{
    Allow,
    Block,
    Log,
    Redirect
}

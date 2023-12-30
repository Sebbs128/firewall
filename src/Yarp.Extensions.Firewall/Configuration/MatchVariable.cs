using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MatchVariable
{
    RequestMethod,
    QueryParam,
    PostArgs,
    RequestPath,
    RequestHeader,
    RequestBody,
    Cookie
}

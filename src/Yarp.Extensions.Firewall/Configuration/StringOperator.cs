using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum StringOperator
{
    Any, // Any is a match all operator. Values aren't checked
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex
}

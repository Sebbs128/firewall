using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NumberOperator
{
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
}

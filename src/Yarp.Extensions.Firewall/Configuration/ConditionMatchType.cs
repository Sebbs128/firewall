using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Conditions for matches
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ConditionMatchType
{
    /// <summary>
    /// Match on the size/length of a request property
    /// </summary>
    Size,
    /// <summary>
    /// Match on a given string value
    /// </summary>
    String,
    /// <summary>
    /// Match on the IP address
    /// </summary>
    IPAddress,
    /// <summary>
    /// Match on the country associated with the IP address
    /// </summary>
    GeoIP
}

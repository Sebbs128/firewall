using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Operating modes for the firewall
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FirewallMode
{
    /// <summary>
    /// Only log matching rules
    /// </summary>
    Detection,
    /// <summary>
    /// Enforce actions on matching rules
    /// </summary>
    Prevention
}

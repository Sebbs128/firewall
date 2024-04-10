using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Actions for a matching rule
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MatchAction
{
    /// <summary>
    /// Allow the request
    /// </summary>
    Allow,
    /// <summary>
    /// Block the request
    /// </summary>
    Block,
    /// <summary>
    /// Log the request
    /// </summary>
    Log,
    /// <summary>
    /// Redirect the client
    /// </summary>
    Redirect
}

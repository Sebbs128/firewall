using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// HTTP Request properties for conditions
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MatchVariable
{
    /// <summary>
    /// HTTP Request Method
    /// </summary>
    RequestMethod,
    /// <summary>
    /// URL Query Parameters
    /// </summary>
    QueryParam,
    /// <summary>
    /// HTTP POST Arguments
    /// </summary>
    PostArgs,
    /// <summary>
    /// The path of the URL
    /// </summary>
    RequestPath,
    /// <summary>
    /// HTTP Request Header
    /// </summary>
    RequestHeader,
    /// <summary>
    /// HTTP Request Body
    /// </summary>
    RequestBody,
    /// <summary>
    /// HTTP Request Cookie
    /// </summary>
    Cookie
}

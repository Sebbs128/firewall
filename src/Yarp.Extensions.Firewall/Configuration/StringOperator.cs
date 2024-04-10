using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Operators for string comparisons
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum StringOperator
{
    /// <summary>
    /// Any value/Match all. Values are not checked.
    /// </summary>
    Any,
    /// <summary>
    /// Actual value equals the target value.
    /// </summary>
    Equals,
    /// <summary>
    /// Actual value contains the target value.
    /// </summary>
    Contains,
    /// <summary>
    /// Actual value begins with the target value.
    /// </summary>
    StartsWith,
    /// <summary>
    /// Actual value ends with the target value.
    /// </summary>
    EndsWith,
    /// <summary>
    /// Actual value matches the target regular expression.
    /// </summary>
    Regex
}

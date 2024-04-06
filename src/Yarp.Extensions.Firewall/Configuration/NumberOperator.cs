using System.Text.Json.Serialization;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Operators for numeric comparisons
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NumberOperator
{
    /// <summary>
    /// Actual value is less than the target value.
    /// </summary>
    LessThan,
    /// <summary>
    /// Actual value is greater than the target value.
    /// </summary>
    GreaterThan,
    /// <summary>
    /// Actual value is less than or equal to the target.
    /// </summary>
    LessThanOrEqual,
    /// <summary>
    /// Actual value is greater than or equal to the target.
    /// </summary>
    GreaterThanOrEqual,
}

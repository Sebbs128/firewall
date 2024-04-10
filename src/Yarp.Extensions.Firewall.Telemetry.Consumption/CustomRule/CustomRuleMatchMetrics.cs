namespace Yarp.Extensions.Firewall.Telemetry.Consumption.CustomRule;

/// <summary>
/// Represents metrics reported by the Yarp.Extensions.Firewall event counters.
/// </summary>
public sealed class CustomRuleMatchMetrics
{
    /// <summary>
    /// Creates a new instance.
    /// </summary>
    public CustomRuleMatchMetrics() => Timestamp = DateTime.UtcNow;

    /// <summary>
    /// Timestamp of when this <see cref="CustomRuleMatchMetrics"/> instance was created.
    /// </summary>
    public DateTime Timestamp { get; internal set; }

    /// <summary>
    /// Number of requests that have matched firewall rules since telemetry was enabled.
    /// </summary>
    public long RulesMatched { get; internal set; }

    /// <summary>
    /// Number of requests blocked by the firewall since telemetry was enabled.
    /// </summary>
    public long RequestsBlocked { get; internal set; }

    /// <summary>
    /// Number of requests logged by the firewall since telemetry was enabled.
    /// </summary>
    public long RequestsLogged { get; internal set; }

    /// <summary>
    /// Number of requests allowed by the firewall since telemetry was enabled.
    /// </summary>
    public long RequestsAllowed { get; internal set; }

    /// <summary>
    /// Number of requests redirected by the firewall since telemetry was enabled.
    /// </summary>
    public long RequestsRedirected { get; internal set; }
}

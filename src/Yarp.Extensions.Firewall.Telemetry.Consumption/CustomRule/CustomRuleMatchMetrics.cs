namespace Yarp.Extensions.Firewall.Telemetry.Consumption.CustomRule;

public sealed class CustomRuleMatchMetrics
{
    public CustomRuleMatchMetrics() => Timestamp = DateTime.UtcNow;

    public DateTime Timestamp { get; internal set; }

    public long RulesMatched { get; internal set; }
    public long RequestsBlocked { get; internal set; }
    public long RequestsLogged { get; internal set; }
    public long RequestsAllowed { get; internal set; }
    public long RequestsRedirected { get; internal set; }
}

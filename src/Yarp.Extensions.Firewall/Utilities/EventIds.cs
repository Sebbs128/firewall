using Microsoft.Extensions.Logging;

namespace Yarp.Extensions.Firewall.Utilities;

internal static class EventIds
{
    public static readonly EventId LoadData = new(1, "ApplyFirewallConfig");
    public static readonly EventId ErrorSignalingChange = new(2, "ApplyFirewallConfigFailed");
    public static readonly EventId ConfigurationDataConversionFailed = new(3, "ConfigurationDataConversionFailed");
    public static readonly EventId RouteFirewallAdded = new(4, "RouteFirewallAdded");
    public static readonly EventId RouteFirewallChanged = new(5, "RouteFirewallChanged");
    public static readonly EventId RouteFirewallRemoved = new(6, "RouteFirewallRemoved");
    public static readonly EventId RouteAdded = new(7, "RouteAdded");
    public static readonly EventId RouteChanged = new(8, "RouteChanged");
    public static readonly EventId RouteRemoved = new(9, "RouteRemoved");
    public static readonly EventId ErrorReloadingConfig = new(10, "ErrorReloadingConfig");
    public static readonly EventId ErrorApplyingConfig = new(11, "ErrorApplyingConfig");
    public static readonly EventId ActionTaken = new(12, "ActionTaken");

    public static readonly EventId FileContentSkipped = new(15, "FileContentSkipped");
}

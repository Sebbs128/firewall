using Microsoft.Extensions.Logging;

namespace Yarp.Extensions.Firewall.Utilities;

#pragma warning disable IDE0090

internal static class EventIds
{
    public static readonly EventId LoadData = new EventId(1, "ApplyFirewallConfig");
    public static readonly EventId ErrorSignalingChange = new EventId(2, "ApplyFirewallConfigFailed");
    public static readonly EventId ConfigurationDataConversionFailed = new EventId(3, "ConfigurationDataConversionFailed");
    public static readonly EventId RouteFirewallAdded = new EventId(4, "RouteFirewallAdded");
    public static readonly EventId RouteFirewallChanged = new EventId(5, "RouteFirewallChanged");
    public static readonly EventId RouteFirewallRemoved = new EventId(6, "RouteFirewallRemoved");
    public static readonly EventId RouteAdded = new EventId(7, "RouteAdded");
    public static readonly EventId RouteChanged = new EventId(8, "RouteChanged");
    public static readonly EventId RouteRemoved = new EventId(9, "RouteRemoved");
    public static readonly EventId ErrorReloadingConfig = new EventId(10, "ErrorReloadingConfig");
    public static readonly EventId ErrorApplyingConfig = new EventId(11, "ErrorApplyingConfig");
    public static readonly EventId ActionTaken = new EventId(12, "ActionTaken");

    public static readonly EventId FileContentSkipped = new EventId(15, "FileContentSkipped");
}

#pragma warning restore IDE0090

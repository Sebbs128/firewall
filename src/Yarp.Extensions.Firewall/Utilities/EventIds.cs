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
    public static readonly EventId ErrorReloadingConfig = new EventId(7, "ErrorReloadingConfig");
    public static readonly EventId ErrorApplyingConfig = new EventId(8, "ErrorApplyingConfig");
    public static readonly EventId ActionTaken = new EventId(9, "ActionTaken");

    public static readonly EventId GeoIPDatabaseOpened = new EventId(20, "GeoIPDatabaseOpened");
}

#pragma warning restore IDE0090

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Extensions for adding MaxMind GeoIP2 Country evaluators
/// </summary>
public static class GeoIPConditionBuilderContextExtensions
{
    /// <summary>
    /// Adds an evaluator for countries based on remote client IP address.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="geoIpDbFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddGeoIpRemoteAddressEvaluator(this ConditionBuilderContext context, GeoIPMatchCondition matchCondition, IGeoIPDatabaseProviderFactory geoIpDbFactory)
    {
        GeoIPRemoteAddressEvaluator evaluator = new(
            matchCondition.MatchCountryValues,
            matchCondition.Negate,
            geoIpDbFactory);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for countries based on socket IP address.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="geoIpDbFactory"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddGeoIpSocketAddressEvaluator(this ConditionBuilderContext context, GeoIPMatchCondition matchCondition, IGeoIPDatabaseProviderFactory geoIpDbFactory)
    {
        GeoIPSocketAddressEvaluator evaluator = new(
            matchCondition.MatchCountryValues,
            matchCondition.Negate,
            geoIpDbFactory);
        context.RuleConditions.Add(evaluator);
        return context;
    }
}

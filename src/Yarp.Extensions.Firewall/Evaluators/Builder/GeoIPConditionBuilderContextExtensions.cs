using MaxMind.GeoIP2;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class GeoIPConditionBuilderContextExtensions
{
    public static ConditionBuilderContext AddGeoIpRemoteAddressEvaluator(this ConditionBuilderContext context, GeoIPMatchCondition matchCondition, IGeoIPDatabaseProviderFactory geoIpDbFactory)
    {
        GeoIPRemoteAddressEvaluator evaluator = new (
            matchCondition.MatchCountryValues,
            matchCondition.Negate,
            geoIpDbFactory);
        context.RuleConditions.Add(evaluator);
        return context;
    }

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

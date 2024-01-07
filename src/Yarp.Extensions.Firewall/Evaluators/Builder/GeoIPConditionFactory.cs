using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;
internal sealed class GeoIPConditionFactory : IConditionFactory
{
    private readonly IGeoIPDatabaseProviderFactory _geoIpDbFactory;

    public GeoIPConditionFactory(IGeoIPDatabaseProviderFactory geoIpDbFactory)
    {
        _geoIpDbFactory = geoIpDbFactory;
    }

    public bool Validate(EvaluatorValidationContext context, MatchCondition condition)
    {
        if (condition is GeoIPMatchCondition geoIPMatchCondition)
        {
            try
            {
                if (_geoIpDbFactory.GetCurrent() is null)
                {
                    context.Errors.Add(new ArgumentException("An existing path for the MaxMind GeoIP2 or GeoLite2 Country database is not configured."));
                }
            }
            catch (InvalidDataException ex) // GeoIPDatabaseFactory throws this if database is not a Country database
            {
                context.Errors.Add(ex);
            }

            return true;
        }

        return false;
    }

    public bool Build(ConditionBuilderContext context, MatchCondition condition)
    {
        if (condition is GeoIPMatchCondition geoIPMatchCondition)
        {
            _ = geoIPMatchCondition.MatchVariable switch
            {
                IPMatchVariable.RemoteAddress => context.AddGeoIpRemoteAddressEvaluator(geoIPMatchCondition, _geoIpDbFactory),
                IPMatchVariable.SocketAddress => context.AddGeoIpSocketAddressEvaluator(geoIPMatchCondition, _geoIpDbFactory),
                _ => throw new ArgumentException($"Unexpected match variable for {nameof(GeoIPMatchCondition)}: {geoIPMatchCondition.MatchVariable}")
            };

            return true;
        }

        return false;
    }
}

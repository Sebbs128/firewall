using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the Country determined from the remote client address of the HTTP request against a list of countries.
/// </summary>
public class GeoIPRemoteAddressEvaluator : ConditionEvaluator
{
    private readonly IGeoIPDatabaseProviderFactory _geoIpDbReader;

    /// <inheritdoc/>
    public GeoIPRemoteAddressEvaluator(IReadOnlyList<string> countries, bool negate, IGeoIPDatabaseProviderFactory geoIpDbFactory) : base(negate)
    {
        Countries = countries;
        _geoIpDbReader = geoIpDbFactory;
    }

    /// <summary>
    /// Countries to match against.
    /// </summary>
    public IReadOnlyList<string> Countries { get; }

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        var clientAddress = context.HttpContext.GetRemoteIPAddress();

        if (clientAddress is not null)
        {
            using var dbProvider = _geoIpDbReader.GetCurrent();
            dbProvider.Get().TryCountry(clientAddress, out var countryResponse);
            foreach (var country in Countries)
            {
                if (country.Equals(countryResponse!.Country.Name, StringComparison.InvariantCultureIgnoreCase))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "GeoIPRemoteAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: countryResponse!.Country.Name));
                    break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

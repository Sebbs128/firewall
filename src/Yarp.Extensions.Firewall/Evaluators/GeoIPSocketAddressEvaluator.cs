using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the Country determined from the socket address of the HTTP request against a list of countries.
/// </summary>
public class GeoIPSocketAddressEvaluator : ConditionEvaluator
{
    private readonly IGeoIPDatabaseProviderFactory _geoIpDbReader;

    /// <inheritdoc/>
    public GeoIPSocketAddressEvaluator(IReadOnlyList<string> countries, bool negate, IGeoIPDatabaseProviderFactory geoIpDbFactory) : base(negate)
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

        var clientAddress = context.HttpContext.Connection.RemoteIpAddress;

        if (clientAddress is not null)
        {
            using var dbProvider = _geoIpDbReader.GetCurrent();
            var requestCountry = dbProvider.LookupCountry(clientAddress);

            if (requestCountry?.Name is not null)
            {
                foreach (var country in Countries)
                {
                    if (country.Equals(requestCountry.Name, StringComparison.InvariantCultureIgnoreCase))
                    {
                        isMatch = true;
                        context.MatchedValues.Add(new EvaluatorMatchValue(
                            MatchVariableName: "GeoIPSocketAddress",
                            OperatorName: "Equals",
                            MatchVariableValue: requestCountry.Name));
                        break;
                    }
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

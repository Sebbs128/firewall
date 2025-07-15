using System.Net;

using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the Country determined from the remote client address of the HTTP request against a list of countries.
/// </summary>
/// <inheritdoc/>
public class GeoIPRemoteAddressEvaluator(IReadOnlyList<string> countries, bool negate, IGeoIPDatabaseProviderFactory geoIpDbFactory) : ConditionEvaluator(negate)
{
    private readonly IGeoIPDatabaseProviderFactory _geoIpDbReader = geoIpDbFactory;

    /// <summary>
    /// Countries to match against.
    /// </summary>
    public IReadOnlyList<string> Countries { get; } = countries;

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;
        using var dbProvider = _geoIpDbReader.GetCurrent();

        // checking each of Forwarded, X-Forwarded-For, and Connection.RemoteIpAddress
        // we can't be sure of the order Forwarded and X-Forwarded-For were appended by any proxies
        // (or if there even were any proxies)

        var clientAddress = context.HttpContext.GetRemoteIPAddressFromForwardedHeader();

        if (clientAddress is not null)
        {
            isMatch = CheckForIPAddressCountryMatch(clientAddress, dbProvider);
            if (isMatch)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "GeoIPRemoteAddress",
                    OperatorName: "Equals",
                    MatchVariableValue: dbProvider.LookupCountry(clientAddress)?.Name ?? string.Empty));
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.GetRemoteIPAddressFromXForwardedForHeader();
            if (clientAddress is not null)
            {
                isMatch = CheckForIPAddressCountryMatch(clientAddress, dbProvider);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "GeoIPRemoteAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: dbProvider.LookupCountry(clientAddress)?.Name ?? string.Empty));
                }
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.Connection.RemoteIpAddress;
            if (clientAddress is not null)
            {
                isMatch = CheckForIPAddressCountryMatch(clientAddress, dbProvider);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "GeoIPRemoteAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: dbProvider.LookupCountry(clientAddress)?.Name ?? string.Empty));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }

    private bool CheckForIPAddressCountryMatch(IPAddress clientAddress, IGeoIPDatabaseProvider dbProvider)
    {
        var requestCountry = dbProvider.LookupCountry(clientAddress);
        if (requestCountry?.Name is not null)
        {
            foreach (var country in Countries)
            {
                if (country.Equals(requestCountry.Name, StringComparison.InvariantCultureIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }
}

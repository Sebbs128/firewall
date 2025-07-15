using System.Diagnostics.CodeAnalysis;
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

        foreach (var clientAddress in context.HttpContext.GetRemoteIPAddressesFromForwardedHeader())
        {
            isMatch = CheckForIPAddressCountryMatch(clientAddress, dbProvider, out var country);
            if (isMatch)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "GeoIPRemoteAddress",
                    OperatorName: "Equals",
                    MatchVariableValue: country!.Name ?? string.Empty));
            }
        }

        if (!isMatch)
        {
            foreach (var clientAddress in context.HttpContext.GetRemoteIPAddressesFromXForwardedForHeader())
            {
                isMatch = CheckForIPAddressCountryMatch(clientAddress, dbProvider, out var country);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "GeoIPRemoteAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: country!.Name ?? string.Empty));
                }
            }
        }

        if (!isMatch)
        {
            var socketAddress = context.HttpContext.Connection.RemoteIpAddress;

            if (socketAddress is not null)
            {
                isMatch = CheckForIPAddressCountryMatch(socketAddress, dbProvider, out var country);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "GeoIPRemoteAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: country!.Name ?? string.Empty));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }

    private bool CheckForIPAddressCountryMatch(
        IPAddress clientAddress,
        IGeoIPDatabaseProvider dbProvider,
        [NotNullWhen(true)] out Country? result)
    {
        result = null;
        var requestCountry = dbProvider.LookupCountry(clientAddress);
        if (requestCountry?.Name is not null)
        {
            foreach (var country in Countries)
            {
                if (country.Equals(requestCountry.Name, StringComparison.InvariantCultureIgnoreCase))
                {
                    result = requestCountry;
                    return true;
                }
            }
        }
        return false;
    }
}

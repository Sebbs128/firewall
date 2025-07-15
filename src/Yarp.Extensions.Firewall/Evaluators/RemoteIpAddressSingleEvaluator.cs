using System.Net;

using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the remote client address from the HTTP request against individual IP addresses.
/// </summary>
/// <inheritdoc/>
public class RemoteIpAddressSingleEvaluator(IReadOnlyList<IPAddress> ipAddresses, bool negate) : ConditionEvaluator(negate)
{
    /// <summary>
    /// IP addresses to match against.
    /// </summary>
    public IReadOnlyList<IPAddress> IpAddresses { get; } = ipAddresses;

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        // checking each of Forwarded, X-Forwarded-For, and Connection.RemoteIpAddress
        // we can't be sure of the order Forwarded and X-Forwarded-For were appended by any proxies
        // (or if there even were any proxies)

        var clientAddress = context.HttpContext.GetRemoteIPAddressFromForwardedHeader();

        if (clientAddress is not null)
        {
            isMatch = CheckForIpAddressMatch(clientAddress);
            if (isMatch)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "RemoteIpAddress",
                    OperatorName: "Equals",
                    MatchVariableValue: clientAddress.ToString()));
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.GetRemoteIPAddressFromXForwardedForHeader();

            if (clientAddress is not null)
            {
                isMatch = CheckForIpAddressMatch(clientAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: clientAddress.ToString()));
                }
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.Connection.RemoteIpAddress;

            if (clientAddress is not null)
            {
                isMatch = CheckForIpAddressMatch(clientAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: clientAddress.ToString()));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }

    private bool CheckForIpAddressMatch(IPAddress? clientAddress)
    {
        foreach (var ipAddress in IpAddresses)
        {
            if (ipAddress.Equals(clientAddress))
            {
                return true;
            }
        }

        return false;
    }
}

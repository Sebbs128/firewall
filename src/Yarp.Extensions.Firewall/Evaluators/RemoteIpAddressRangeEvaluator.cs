using System.Net;

using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the remote client address from the HTTP request against IP address ranges.
/// </summary>
/// <inheritdoc/>
public class RemoteIpAddressRangeEvaluator(IReadOnlyList<IPNetwork> ipAddressRanges, bool negate) : ConditionEvaluator(negate)
{
    /// <summary>
    /// IP address ranges to match against.
    /// </summary>
    public IReadOnlyList<IPNetwork> IpAddressRanges { get; } = ipAddressRanges;

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
            isMatch = CheckForIpAddressInRange(clientAddress);
            if (isMatch)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "RemoteIpAddress",
                    OperatorName: "InRange",
                    MatchVariableValue: clientAddress.ToString()!));
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.GetRemoteIPAddressFromXForwardedForHeader();
            if (clientAddress is not null)
            {
                isMatch = CheckForIpAddressInRange(clientAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "InRange",
                        MatchVariableValue: clientAddress.ToString()!));
                }
            }
        }

        if (!isMatch)
        {
            clientAddress = context.HttpContext.Connection.RemoteIpAddress;
            if (clientAddress is not null)
            {
                isMatch = CheckForIpAddressInRange(clientAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "InRange",
                        MatchVariableValue: clientAddress.ToString()!));
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }

    private bool CheckForIpAddressInRange(IPAddress clientAddress)
    {
        foreach (var ipAddressRange in IpAddressRanges)
        {
            if (ipAddressRange.Contains(clientAddress))
            {
                return true;
            }
        }
        return false;
    }
}

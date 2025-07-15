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

        foreach (var clientAddress in context.HttpContext.GetRemoteIPAddressesFromForwardedHeader())
        {
            isMatch = CheckForIpAddressInRange(clientAddress);
            if (isMatch)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "RemoteIpAddress",
                    OperatorName: "InRange",
                    MatchVariableValue: clientAddress.ToString()!));
                break;
            }
        }

        if (!isMatch)
        {
            foreach (var clientAddress in context.HttpContext.GetRemoteIPAddressesFromXForwardedForHeader())
            {
                isMatch = CheckForIpAddressInRange(clientAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "InRange",
                        MatchVariableValue: clientAddress.ToString()!));
                    break;
                }
            }
        }

        if (!isMatch)
        {
            var socketAddress = context.HttpContext.Connection.RemoteIpAddress;
            if (socketAddress is not null)
            {
                isMatch = CheckForIpAddressInRange(socketAddress);
                if (isMatch)
                {
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "InRange",
                        MatchVariableValue: socketAddress.ToString()!));
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

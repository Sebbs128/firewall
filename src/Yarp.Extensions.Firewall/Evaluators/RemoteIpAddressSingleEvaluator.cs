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

        var clientAddress = context.HttpContext.GetRemoteIPAddress();

        if (clientAddress is not null)
        {
            foreach (var ipAddress in IpAddresses)
            {
                if (ipAddress.Equals(clientAddress))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: ipAddress.ToString()));
                    break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

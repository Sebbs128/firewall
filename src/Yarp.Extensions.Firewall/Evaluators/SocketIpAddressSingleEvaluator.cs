using System.Net;

using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the socket address from the HTTP request against individual IP addresses.
/// </summary>
/// <inheritdoc/>
public sealed class SocketIpAddressSingleEvaluator(IReadOnlyList<IPAddress> ipAddresses, bool negate) : ConditionEvaluator(negate)
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

        var clientAddress = context.HttpContext.Connection.RemoteIpAddress;

        if (clientAddress is not null)
        {
            foreach (var ipAddress in IpAddresses)
            {
                if (ipAddress.Equals(clientAddress))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "SocketIpAddress",
                        OperatorName: "Equals",
                        MatchVariableValue: ipAddress.ToString())); break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

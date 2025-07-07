using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the socket address from the HTTP request against IP address ranges.
/// </summary>
/// <inheritdoc/>
public class SocketIpAddressRangeEvaluator(IReadOnlyList<IPNetwork> ipAddressRanges, bool negate) : ConditionEvaluator(negate)
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

        var clientAddress = context.HttpContext.Connection.RemoteIpAddress;

        if (clientAddress is not null)
        {
            foreach (var ipAddressRange in IpAddressRanges)
            {
                if (ipAddressRange.Contains(clientAddress))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "SocketIpAddress",
                        OperatorName: "InRange",
                        MatchVariableValue: ipAddressRange.ToString()!));
                    break;
                }
            }
        }

        //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
        return ValueTask.FromResult(Negate ^ isMatch);
    }
}

using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the remote client address from the HTTP request against IP address ranges.
/// </summary>
public class RemoteIpAddressRangeEvaluator : ConditionEvaluator
{
    /// <inheritdoc/>
    public RemoteIpAddressRangeEvaluator(IReadOnlyList<IPNetwork> ipAddressRanges, bool negate)
        : base(negate)
    {
        IpAddressRanges = ipAddressRanges;
    }

    /// <summary>
    /// IP address ranges to match against.
    /// </summary>
    public IReadOnlyList<IPNetwork> IpAddressRanges { get; }

    /// <inheritdoc/>
    public override ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var isMatch = false;

        var clientAddress = context.HttpContext.GetRemoteIPAddress();

        if (clientAddress is not null)
        {
            foreach (var ipAddressRange in IpAddressRanges)
            {
                if (ipAddressRange.Contains(clientAddress))
                {
                    isMatch = true;
                    context.MatchedValues.Add(new EvaluatorMatchValue(
                        MatchVariableName: "RemoteIpAddress",
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

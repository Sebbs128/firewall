using System.Net;

using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

public sealed class SocketIpAddressSingleEvaluator : ConditionEvaluator
{
    public SocketIpAddressSingleEvaluator(IReadOnlyList<IPAddress> ipAddresses, bool negate)
        : base(negate)
    {
        IpAddresses = ipAddresses;
    }

    public IReadOnlyList<IPAddress> IpAddresses { get; }

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

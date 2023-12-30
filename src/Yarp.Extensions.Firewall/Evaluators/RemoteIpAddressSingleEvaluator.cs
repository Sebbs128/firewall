﻿using System.Net;

using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RemoteIpAddressSingleEvaluator : ConditionEvaluator
{
    public RemoteIpAddressSingleEvaluator(IReadOnlyList<IPAddress> ipAddresses, bool negate)
        : base(negate)
    {
        IpAddresses = ipAddresses;
    }

    public IReadOnlyList<IPAddress> IpAddresses { get; }

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

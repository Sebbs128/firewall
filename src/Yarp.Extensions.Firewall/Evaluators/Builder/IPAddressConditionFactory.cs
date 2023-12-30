using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

internal sealed class IPAddressConditionFactory : IConditionFactory
{
    public bool Validate(EvaluatorValidationContext context, MatchCondition condition)
    {
        if (condition is IPAddressMatchCondition ipAddressCondition)
        {
            if (ipAddressCondition.IPAddressOrRanges.Contains('/', StringComparison.OrdinalIgnoreCase))
            {
                IPAddressHelpers.TryParseCidrRanges(context, ipAddressCondition.IPAddressOrRanges);
            }
            else
            {
                IPAddressHelpers.TryParseIpAddresses(context, ipAddressCondition.IPAddressOrRanges);
            }

            return true;
        }

        return false;
    }

    public bool Build(ConditionBuilderContext context, MatchCondition condition)
    {
        if (condition is IPAddressMatchCondition ipAddressCondition)
        {
            if (ipAddressCondition.IPAddressOrRanges.Contains('/', StringComparison.OrdinalIgnoreCase))
            {
                var ipAddressRanges = IPAddressHelpers.ParseCidrRanges(ipAddressCondition.IPAddressOrRanges);

                _ = ipAddressCondition.MatchVariable switch
                {
                    IPMatchVariable.RemoteAddress => context.AddRemoteIpAddressRangeEvaluator(ipAddressCondition, ipAddressRanges),
                    IPMatchVariable.SocketAddress => context.AddSocketIpAddressRangeEvaluator(ipAddressCondition, ipAddressRanges),
                    _ => throw new ArgumentException($"Unexpected match variable for {nameof(IPAddressMatchCondition)}: {ipAddressCondition.MatchVariable}")
                };
            }
            else
            {
                var ipAddresses = IPAddressHelpers.ParseIpAddresses(ipAddressCondition.IPAddressOrRanges);

                _ = ipAddressCondition.MatchVariable switch
                {
                    IPMatchVariable.RemoteAddress => context.AddRemoteIpAddressEvaluator(ipAddressCondition, ipAddresses),
                    IPMatchVariable.SocketAddress => context.AddSocketIpAddressEvaluator(ipAddressCondition, ipAddresses),
                    _ => throw new ArgumentException($"Unexpected match variable for {nameof(IPAddressMatchCondition)}: {ipAddressCondition.MatchVariable}")
                };
            }

            return true;
        }

        return false;
    }
}

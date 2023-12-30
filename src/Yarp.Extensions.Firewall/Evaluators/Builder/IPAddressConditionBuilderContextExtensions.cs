using System.Net;
using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class IPAddressConditionBuilderContextExtensions
{
    public static ConditionBuilderContext AddRemoteIpAddressEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPAddress> ipAddresses)
    {
        RemoteIpAddressSingleEvaluator evaluator = new(
            ipAddresses,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddSocketIpAddressEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPAddress> ipAddresses)
    {
        SocketIpAddressSingleEvaluator evaluator = new(
            ipAddresses,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }
    public static ConditionBuilderContext AddRemoteIpAddressRangeEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPNetwork> ipAddressRanges)
    {
        RemoteIpAddressRangeEvaluator evaluator = new(
            ipAddressRanges,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    public static ConditionBuilderContext AddSocketIpAddressRangeEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPNetwork> ipAddressRanges)
    {
        SocketIpAddressRangeEvaluator evaluator = new(
            ipAddressRanges,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }
}

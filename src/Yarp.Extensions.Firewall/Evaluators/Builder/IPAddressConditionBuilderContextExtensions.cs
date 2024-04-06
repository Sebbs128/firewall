using System.Net;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Extensions for adding IP address evaluators
/// </summary>
public static class IPAddressConditionBuilderContextExtensions
{
    /// <summary>
    /// Adds an evaluator for remote client IP addresses.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="ipAddresses"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRemoteIpAddressEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPAddress> ipAddresses)
    {
        RemoteIpAddressSingleEvaluator evaluator = new(
            ipAddresses,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for socket IP addresses.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="ipAddresses"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddSocketIpAddressEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPAddress> ipAddresses)
    {
        SocketIpAddressSingleEvaluator evaluator = new(
            ipAddresses,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for remote client IP address ranges.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="ipAddressRanges"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddRemoteIpAddressRangeEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPNetwork> ipAddressRanges)
    {
        RemoteIpAddressRangeEvaluator evaluator = new(
            ipAddressRanges,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }

    /// <summary>
    /// Adds an evaluator for socket IP address ranges.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="matchCondition"></param>
    /// <param name="ipAddressRanges"></param>
    /// <returns></returns>
    public static ConditionBuilderContext AddSocketIpAddressRangeEvaluator(this ConditionBuilderContext context, IPAddressMatchCondition matchCondition, IReadOnlyList<IPNetwork> ipAddressRanges)
    {
        SocketIpAddressRangeEvaluator evaluator = new(
            ipAddressRanges,
            matchCondition.Negate);
        context.RuleConditions.Add(evaluator);
        return context;
    }
}

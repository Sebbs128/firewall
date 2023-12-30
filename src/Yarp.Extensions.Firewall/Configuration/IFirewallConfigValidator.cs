namespace Yarp.Extensions.Firewall.Configuration;

public interface IFirewallConfigValidator
{
    ValueTask<IList<Exception>> ValidateFirewall(RouteFirewallConfig firewall);
}

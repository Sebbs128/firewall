namespace Yarp.Extensions.Firewall.Configuration;

public interface IFirewallConfigProvider
{
    IFirewallConfig GetConfig();
}

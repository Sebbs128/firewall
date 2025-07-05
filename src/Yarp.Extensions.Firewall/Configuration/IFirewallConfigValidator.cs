namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Provides methods to validation firewalls.
/// </summary>
public interface IFirewallConfigValidator
{
    /// <summary>
    /// Validates a firewall and returns all errors.
    /// </summary>
    /// <param name="firewall"></param>
    /// <returns></returns>
    public ValueTask<IList<Exception>> ValidateFirewall(RouteFirewallConfig firewall);
}

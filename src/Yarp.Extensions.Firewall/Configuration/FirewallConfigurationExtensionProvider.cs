using Microsoft.Extensions.Configuration;

namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Base class for firewall configuration extension providers.
/// </summary>
/// <typeparam name="T">The type of the extended configuration that this provider handles.</typeparam>
public abstract class FirewallConfigurationExtensionProvider<T>
    : IFirewallConfigurationExtensionProvider where T : class, new()
{
    /// <inheritdoc/>
    public Type Type => typeof(T);

    /// <inheritdoc/>
    public virtual object GetExtendedConfiguration(IConfiguration configuration)
    {
        // may or may not allow source-generated configuration binding in future
        var t = new T();
        configuration.GetSection(typeof(T).Name).Bind(t);
        return t;
    }
}

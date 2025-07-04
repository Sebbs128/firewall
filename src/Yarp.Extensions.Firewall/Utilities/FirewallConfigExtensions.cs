#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Yarp.Extensions.Firewall.Configuration;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>  
/// Provides extension methods for <see cref="IFirewallConfig"/> to access extended configuration.  
/// </summary>  
public static class FirewallConfigExtensions
{
    /// <summary>  
    /// Retrieves an extended configuration object of the specified type from the firewall configuration.  
    /// </summary>  
    /// <typeparam name="T">The type of the extended configuration object to retrieve.</typeparam>  
    /// <param name="config">The firewall configuration instance.</param>  
    /// <returns>The extended configuration object if found; otherwise, <c>null</c>.</returns>  
    public static T? GetExtendedConfiguration<T>(this IFirewallConfig config)
        where T : class
    {
        return config.ConfigurationExtensions.TryGetValue(typeof(T), out var value) && value is T t
            ? t
            : null;
    }
}

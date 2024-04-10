using Yarp.Extensions.Firewall;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extensions for <see cref="IReverseProxyApplicationBuilder"/>
/// used to add the Firewall to the ASP.NET Core request pipeline.
/// </summary>
public static class AppBuilderExtensions
{
    /// <summary>
    /// Adds Firewall middleware to the Reverse Proxy
    /// </summary>
    public static IReverseProxyApplicationBuilder UseFirewall(this IReverseProxyApplicationBuilder builder)
    {
        builder.UseMiddleware<CustomRuleMiddleware>();

        return builder;
    }
}

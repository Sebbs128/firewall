using Microsoft.Extensions.DependencyInjection;

using Yarp.Extensions.Firewall;
using Yarp.Extensions.Firewall.Management;

namespace Microsoft.AspNetCore.Builder;

public static class AppBuilderExtensions
{
    public static IReverseProxyApplicationBuilder UseFirewall(this IReverseProxyApplicationBuilder builder)
    {
        builder.UseMiddleware<CustomRuleMiddleware>();

        return builder;
    }
}

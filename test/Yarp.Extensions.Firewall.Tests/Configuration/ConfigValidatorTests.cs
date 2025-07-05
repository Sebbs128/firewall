using Microsoft.Extensions.DependencyInjection;

using Yarp.Extensions.Firewall.Common.Tests.GeoIP;
using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;

namespace Yarp.Extensions.Firewall.Tests.Configuration;
public class ConfigValidatorTests
{
    private IServiceProvider CreateServices(Action<IServiceCollection> configure = null)
    {
        var services = new ServiceCollection();
        services.AddReverseProxy()
            .AddFirewall()
            .Services.AddSingleton<IGeoIPDatabaseProviderFactory, DummyGeoIPDatabaseProviderFactory>();
        services.AddOptions();
        services.AddLogging();
        services.AddRouting();
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void Constructor_Works()
    {
        var services = CreateServices();
        services.GetRequiredService<IFirewallConfigValidator>();
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task Rejects_MissingRouteId(string routeId)
    {
        var routeFirewall = new RouteFirewallConfig { RouteId = routeId };

        var services = CreateServices();
        var validator = services.GetRequiredService<IFirewallConfigValidator>();

        var result = await validator.ValidateFirewall(routeFirewall);

        Assert.NotEmpty(result);
        Assert.Contains(result, err => err.Message.Equals("Missing Route Id."));
    }
}

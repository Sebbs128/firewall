using System.Net;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Xunit.Abstractions;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.Extensions.Firewall.FunctionalTests.Common;

public class TestEnvironment
{
    public HttpStatusCode BlockedStatusCode { get; set; }

    public Action<IServiceCollection> ConfigureDestinationServices { get; set; } = _ => { };

    public Action<IApplicationBuilder> ConfigureDestinationApp { get; set; } = _ => { };

    public FirewallMode FirewallMode { get; set; } = FirewallMode.Prevention;

    public IReadOnlyList<RuleConfig> FirewallRules { get; set; } = new List<RuleConfig>();

    public string RedirectUri { get; set; } = "http://localhost/blocked";

    public ITestOutputHelper TestOutput { get; set; }
    public string GeoIPDatabasePath { get; set; } = string.Empty;

    public TestEnvironment() { }

    public TestEnvironment(RequestDelegate destinationGetDelegate)
    {
        ConfigureDestinationApp = destinationApp =>
        {
            destinationApp.Run(destinationGetDelegate);
        };
    }

    public async Task Invoke(Func<string, Task> clientFunc, CancellationToken cancellationToken = default)
    {
        using var destination = CreateHost(ConfigureDestinationServices, ConfigureDestinationApp);
        await destination.StartAsync(cancellationToken);

        using var proxy = CreateProxy(destination.GetAddress());
        await proxy.StartAsync(cancellationToken);

        try
        {
            await clientFunc(proxy.GetAddress());
        }
        finally
        {
            await proxy.StopAsync(cancellationToken);
            await destination.StopAsync(cancellationToken);
        }
    }

    private IHost CreateProxy(string destinationAddress)
    {
        return CreateHost(services =>
        {
            var route = new RouteConfig
            {
                RouteId = "route1",
                ClusterId = "cluster1",
                Match = new RouteMatch { Path = "/{**catchall}" }
            };

            var cluster = new ClusterConfig
            {
                ClusterId = "cluster1",
                Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
                {
                    { "destination1",  new DestinationConfig() { Address = destinationAddress } }
                }
            };

            var firewall = new RouteFirewallConfig()
            {
                RouteId = "route1",
                Enabled = true,
                Mode = FirewallMode,
                RedirectUri = RedirectUri,
                BlockedStatusCode = BlockedStatusCode,
                Rules = FirewallRules
            };

            var proxyBuilder = services.AddReverseProxy()
                .LoadFromMemory(new[] { route }, new[] { cluster })
                .AddFirewall()
                .LoadFromMemory(new[] { firewall }, GeoIPDatabasePath);
        },
        app =>
        {
            app.UseRouting();
            app.UseEndpoints(builder =>
            {
                builder.MapReverseProxy(proxyAppBuilder =>
                {
                    proxyAppBuilder.UseFirewall();
                });
            });
        });
    }

    private IHost CreateHost(Action<IServiceCollection> configureServices, Action<IApplicationBuilder> configureApp)
    {
        return new HostBuilder()
            .ConfigureAppConfiguration(config =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string>()
                {
                    { "Logging:LogLevel:Microsoft", "Trace" },
                    { "Logging:LogLevel:Microsoft.AspNetCore.Hosting.Diagnostics", "Information" }
                });
            })
            .ConfigureLogging((hostingContext, loggingBuilder) =>
            {
                loggingBuilder.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                loggingBuilder.AddEventSourceLogger();
                loggingBuilder.AddDebug();
            })
            .ConfigureWebHost(webHostBuilder =>
            {
                webHostBuilder
                    .ConfigureServices(configureServices)
                    .UseKestrel(kestrel =>
                    {
                        kestrel.Listen(IPAddress.Loopback, 0);
                    })
                    .Configure(configureApp);
            })
            .Build();
    }
}

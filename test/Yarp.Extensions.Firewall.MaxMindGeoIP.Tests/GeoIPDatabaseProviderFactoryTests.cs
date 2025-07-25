using System.Net;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using NSubstitute;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Management;
using Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;
using Yarp.Extensions.Firewall.MaxMindGeoIP.Tests.Common;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Tests;
public class GeoIPDatabaseProviderFactoryTests
{
    private static IServiceProvider CreateServices(
        List<RouteFirewallConfig> firewalls,
        Dictionary<Type, object> componentExtensions)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddRouting();
        var proxyBuilder = serviceCollection.AddReverseProxy();
        proxyBuilder.AddFirewall().LoadFromMemory(firewalls, componentExtensions)
            .AddMaxMindGeoIP();

        serviceCollection.TryAddSingleton(Substitute.For<IServer>());
        serviceCollection.TryAddSingleton(Substitute.For<IWebHostEnvironment>());

        return serviceCollection.BuildServiceProvider();
    }

    private static IServiceProvider CreateServices(
        IEnumerable<IFirewallConfigProvider> firewallConfigProviders)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddRouting();

        var proxyBuilder = serviceCollection.AddReverseProxy();

        proxyBuilder.AddFirewall()
            .AddMaxMindGeoIP();
        foreach (var configProvider in firewallConfigProviders)
        {
            serviceCollection.AddSingleton(configProvider);
        }

        serviceCollection.TryAddSingleton(Substitute.For<IServer>());
        serviceCollection.TryAddSingleton(Substitute.For<IWebHostEnvironment>());

        return serviceCollection.BuildServiceProvider();
    }


    [Fact]
    public void Constructor_Works()
    {
        var services = CreateServices([], []);
        _ = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
    }

    [Fact]
    public void GetDatabaseReader_WhenDbPathIsEmpty_ReturnsNull()
    {
        var services = CreateServices([], []);
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Null(factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbPathDoesNotExist_ThrowsFileNotFoundException()
    {
        var services = CreateServices([], new Dictionary<Type, object> { [typeof(GeoIPDatabaseConfig)] = TestResources.GetGeoIPDatabaseConfig("NonExistentFile") });
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Throws<FileNotFoundException>(() => factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbIsNotCountryDb_ThrowsInvalidDataException()
    {
        var services = CreateServices([], new Dictionary<Type, object> { [typeof(GeoIPDatabaseConfig)] = TestResources.GetGeoIPDatabaseConfig("GeoLite2-City.mmdb") });
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Throws<InvalidDataException>(() => factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbIsCountryDb_Works()
    {
        var services = CreateServices([], new Dictionary<Type, object> { [typeof(GeoIPDatabaseConfig)] = TestResources.GetGeoIPDatabaseConfig("GeoLite2-Country.mmdb") });
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        var dbProvider = factory.GetCurrent();

        Assert.NotNull(dbProvider);
        Assert.Equal("United States", dbProvider.LookupCountry(new IPAddress([128, 101, 101, 101])).Name); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
    }

    [Fact]
    public void GetDatabaseReader_TwoDistinctConfigs_Works()
    {
        var firewall1 = new RouteFirewallConfig
        {
            RouteId = "route1",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };
        var firewall2 = new RouteFirewallConfig
        {
            RouteId = "route2",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };

        var config1 = new InMemoryConfigProvider(
            [firewall1],
            new Dictionary<Type, object>());
        var config2 = new InMemoryConfigProvider(
            [firewall2],
            new Dictionary<Type, object>()
            {
                {
                    typeof(GeoIPDatabaseConfig),
                    new GeoIPDatabaseConfig
                    {
                        GeoIPDatabasePath = TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb")
                    }
                }
            });

        var services = CreateServices([config1, config2]);

        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        var dbProvider = factory.GetCurrent();
        Assert.NotNull(dbProvider);
        Assert.NotNull(dbProvider.LookupCountry(new IPAddress([128, 101, 101, 101]))); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
    }

    [Fact]
    public void GetDatabaseReader_CanBeUpdated()
    {
        var firewall1 = new RouteFirewallConfig
        {
            RouteId = "route1",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };
        var firewall2 = new RouteFirewallConfig
        {
            RouteId = "route2",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules =
            [
                new()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions =
                    [
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = ["1"]
                        }
                    ]
                }
            ]
        };

        var config1 = new InMemoryConfigProvider([firewall1], new Dictionary<Type, object>());
        var config2 = new InMemoryConfigProvider([firewall2], new Dictionary<Type, object>());

        var services = CreateServices([config1, config2]);

        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Null(factory.GetCurrent());

        config2.Update([firewall2], new Dictionary<Type, object> { { typeof(GeoIPDatabaseConfig), TestResources.GetGeoIPDatabaseConfig("GeoLite2-Country.mmdb") } });

        var dbProvider = factory.GetCurrent();
        Assert.NotNull(dbProvider);
        Assert.NotNull(dbProvider.LookupCountry(new IPAddress([128, 101, 101, 101]))); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
    }
}

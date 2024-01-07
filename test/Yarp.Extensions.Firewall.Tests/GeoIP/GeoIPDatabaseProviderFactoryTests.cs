using System.Net;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using NSubstitute;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Tests.Common;

namespace Yarp.Extensions.Firewall.Tests.GeoIP;
public class GeoIPDatabaseProviderFactoryTests
{
    private static IServiceProvider CreateServices(
        List<RouteFirewallConfig> firewalls,
        string geoIpDbPath)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddRouting();
        var proxyBuilder = serviceCollection.AddReverseProxy();
        proxyBuilder.AddFirewall().LoadFromMemory(firewalls, geoIpDbPath);

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

        proxyBuilder.AddFirewall();
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
        var services = CreateServices(new List<RouteFirewallConfig>(), string.Empty);
        _ = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
    }

    [Fact]
    public void GetDatabaseReader_WhenDbPathIsEmpty_ReturnsNull()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), string.Empty);
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Null(factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbPathDoesNotExist_ReturnsNull()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), TestResources.GetGeoIPDatabasePath("NonExistentFile"));
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Null(factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbIsNotCountryDb_ThrowsInvalidDataException()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), TestResources.GetGeoIPDatabasePath("GeoLite2-City.mmdb"));
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Throws<InvalidDataException>(() => factory.GetCurrent());
    }

    [Fact]
    public void GetDatabaseReader_WhenDbIsCountryDb_Works()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));
        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        var dbProvider = factory.GetCurrent();
        Assert.NotNull(dbProvider);
        Assert.Equal("United States", dbProvider.Get().Country("128.101.101.101").Country.Name); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
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
            Rules = new List<RuleConfig>
            {
                new RuleConfig()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions = new List<MatchCondition>()
                    {
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = new[] { "1" }
                        }
                    }
                }
            }
        };
        var firewall2 = new RouteFirewallConfig
        {
            RouteId = "route2",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules = new List<RuleConfig>
            {
                new RuleConfig()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions = new List<MatchCondition>()
                    {
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = new[] { "1" }
                        }
                    }
                }
            }
        };

        var config1 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall1 }, string.Empty);
        var config2 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall2 }, TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));

        var services = CreateServices(new[] { config1, config2 });

        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        var dbProvider = factory.GetCurrent();
        Assert.NotNull(dbProvider);
        Assert.NotNull(dbProvider.Get().Country("128.101.101.101")); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
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
            Rules = new List<RuleConfig>
            {
                new RuleConfig()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions = new List<MatchCondition>()
                    {
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = new[] { "1" }
                        }
                    }
                }
            }
        };
        var firewall2 = new RouteFirewallConfig
        {
            RouteId = "route2",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = HttpStatusCode.Forbidden,
            Rules = new List<RuleConfig>
            {
                new RuleConfig()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Allow,
                    Conditions = new List<MatchCondition>()
                    {
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = new[] { "1" }
                        }
                    }
                }
            }
        };

        var config1 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall1 }, string.Empty);
        var config2 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall2 }, string.Empty);

        var services = CreateServices(new[] { config1, config2 });

        var factory = services.GetRequiredService<IGeoIPDatabaseProviderFactory>();
        Assert.Null(factory.GetCurrent());

        config2.Update(new List<RouteFirewallConfig> { firewall2 }, TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));

        var dbProvider = factory.GetCurrent();
        Assert.NotNull(dbProvider);
        Assert.NotNull(dbProvider.Get().Country("128.101.101.101")); // IP address from GeoIP2-dotnet examples at https://github.com/maxmind/GeoIP2-dotnet#city-database
    }
}

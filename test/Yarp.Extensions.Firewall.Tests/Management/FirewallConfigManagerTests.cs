using System.Net;
using System.Reflection;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Primitives;

using NSubstitute;

using Yarp.Extensions.Firewall.Common.Tests.GeoIP;
using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.Management;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Configuration;

using InMemoryConfigProvider = Yarp.Extensions.Firewall.Configuration.InMemoryConfigProvider;
using YarpInMemoryConfigProvider = Yarp.ReverseProxy.Configuration.InMemoryConfigProvider;

namespace Yarp.Extensions.Firewall.Tests.Management;
public class FirewallConfigManagerTests
{
    private static IServiceProvider CreateServices(
        List<RouteFirewallConfig> firewalls,
        List<RouteConfig> routes,
        List<ClusterConfig> clusters)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddRouting();
        var proxyBuilder = serviceCollection.AddReverseProxy().LoadFromMemory(routes, clusters);
        proxyBuilder.AddFirewall().LoadFromMemory(firewalls, new Dictionary<Type, object>())
            .Services.AddSingleton<IGeoIPDatabaseProviderFactory, DummyGeoIPDatabaseProviderFactory>();

        serviceCollection.TryAddSingleton(Substitute.For<IServer>());
        serviceCollection.TryAddSingleton(Substitute.For<IWebHostEnvironment>());

        return serviceCollection.BuildServiceProvider();
    }

    private static IServiceProvider CreateServices(
        IEnumerable<IFirewallConfigProvider> firewallConfigProviders,
        IEnumerable<IProxyConfigProvider> proxyConfigProviders,
        IEnumerable<IFirewallConfigChangeListener> configListeners = null)
    {
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddLogging();
        serviceCollection.AddRouting();

        var proxyBuilder = serviceCollection.AddReverseProxy();
        foreach (var configProvider in proxyConfigProviders)
        {
            serviceCollection.AddSingleton(configProvider);
        }

        proxyBuilder.AddFirewall()
            .Services.AddSingleton<IGeoIPDatabaseProviderFactory, DummyGeoIPDatabaseProviderFactory>();
        foreach (var configProvider in firewallConfigProviders)
        {
            serviceCollection.AddSingleton(configProvider);
        }

        serviceCollection.TryAddSingleton(Substitute.For<IServer>());
        serviceCollection.TryAddSingleton(Substitute.For<IWebHostEnvironment>());

        if (configListeners is not null)
        {
            foreach (var configListener in configListeners)
            {
                serviceCollection.AddSingleton(configListener);
            }
        }

        return serviceCollection.BuildServiceProvider();
    }

    [Fact]
    public void Constructor_Works()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), new List<RouteConfig>(), new List<ClusterConfig>());
        _ = services.GetRequiredService<FirewallConfigManager>();
    }

    [Fact]
    public async Task Lookup_StartsEmpty()
    {
        var services = CreateServices(new List<RouteFirewallConfig>(), new List<RouteConfig>(), new List<ClusterConfig>());
        var manager = services.GetRequiredService<FirewallConfigManager>();
        var lookup = services.GetRequiredService<IFirewallStateLookup>();
        await manager.InitialLoadAsync();

        Assert.Empty(lookup.GetRouteFirewalls());
        Assert.False(lookup.TryGetRouteFirewall("route1", out var _));
    }

    [Fact]
    public void BuildConfig_OneRouteFirewall_Works()
    {
        const string TestAddress = "https://localhost:123/";

        var firewall = new RouteFirewallConfig()
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
        var cluster = new ClusterConfig
        {
            ClusterId = "cluster1",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d1", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route = new RouteConfig
        {
            RouteId = "route1",
            ClusterId = "cluster1",
            Match = new RouteMatch { Path = "/" }
        };

        var services = CreateServices(new List<RouteFirewallConfig> { firewall }, new List<RouteConfig> { route }, new List<ClusterConfig> { cluster });

        ProxyConfigManagerInitialLoadAsync(services);

        var lookup = services.GetRequiredService<IFirewallStateLookup>();
        // Initial load of Firewall config is automatically done via an IConfigChangeListener from ProxyConfigManager
        //var manager = services.GetRequiredService<FirewallConfigManager>();
        //await manager.InitialLoadAsync();

        Assert.True(lookup.TryGetRouteFirewall("route1", out var routeFirewallModel));
        Assert.Equal(firewall, routeFirewallModel.Config);
        routeFirewallModel = Assert.Single(lookup.GetRouteFirewalls());
        Assert.Equal(firewall, routeFirewallModel.Config);
    }

    [Fact]
    public async Task BuildConfig_DuplicateRouteIds_Throws()
    {
        var firewall = new RouteFirewallConfig
        {
            RouteId = "route1"
        };

        var services = CreateServices(new List<RouteFirewallConfig> { firewall, firewall }, new List<RouteConfig>(), new List<ClusterConfig>());

        var manager = services.GetRequiredService<FirewallConfigManager>();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => manager.InitialLoadAsync());
        Assert.Contains("Duplicate route firewall 'route1'", ex.ToString());
    }

    [Fact]
    public void BuildConfig_TwoDistinctConfigs_Works()
    {
        const string TestAddress = "https://localhost:123/";

        var firewall1 = new RouteFirewallConfig
        {
            RouteId = "route1",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = System.Net.HttpStatusCode.Forbidden,
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
        var cluster1 = new ClusterConfig
        {
            ClusterId = "cluster1",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d1", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route1 = new RouteConfig
        {
            RouteId = "route1",
            ClusterId = "cluster1",
            Match = new RouteMatch { Path = "/" }
        };

        var firewall2 = new RouteFirewallConfig
        {
            RouteId = "route2",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = System.Net.HttpStatusCode.Forbidden,
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
        var cluster2 = new ClusterConfig
        {
            ClusterId = "cluster2",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d2", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route2 = new RouteConfig
        {
            RouteId = "route2",
            ClusterId = "cluster2",
            Match = new RouteMatch { Path = "/" }
        };

        var config1 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall1 }, new Dictionary<Type, object>());
        var config2 = new InMemoryConfigProvider(new List<RouteFirewallConfig> { firewall2 }, new Dictionary<Type, object>());
        var proxyConfig1 = new YarpInMemoryConfigProvider(new List<RouteConfig> { route1 }, new List<ClusterConfig> { cluster1 });
        var proxyConfig2 = new YarpInMemoryConfigProvider(new List<RouteConfig> { route2 }, new List<ClusterConfig> { cluster2 });

        var services = CreateServices(new[] { config1, config2 }, new[] { proxyConfig1, proxyConfig2 });

        ProxyConfigManagerInitialLoadAsync(services);

        var lookup = services.GetRequiredService<IFirewallStateLookup>();
        // Initial load of Firewall config is automatically done via an IConfigChangeListener from ProxyConfigManager
        //var manager = services.GetRequiredService<FirewallConfigManager>();
        //await manager.InitialLoadAsync();

        Assert.True(lookup.TryGetRouteFirewall("route1", out var firewallModel));
        Assert.NotNull(firewallModel.Config);
        Assert.Equal("route1", firewallModel.Config.RouteId);

        Assert.True(lookup.TryGetRouteFirewall("route2", out firewallModel));
        Assert.NotNull(firewallModel.Config);
        Assert.Equal("route2", firewallModel.Config.RouteId);
    }

    [Fact]
    public void BuildConfig_CanBeNotifiedOfProxyConfigSuccessfulAndFailedLoading()
    {
        const string TestAddress = "https://localhost:123/";

        var configProviderA = new OnDemandFailingInMemoryConfigProvider(new List<RouteFirewallConfig>(), "A1");
        var configProviderB = new OnDemandFailingInMemoryConfigProvider(new List<RouteFirewallConfig>(), "B1");

        var cluster1 = new ClusterConfig
        {
            ClusterId = "cluster1",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d1", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route1 = new RouteConfig
        {
            RouteId = "route1",
            ClusterId = "cluster1",
            Match = new RouteMatch { Path = "/" }
        };

        var cluster2 = new ClusterConfig
        {
            ClusterId = "cluster2",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d2", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route2 = new RouteConfig
        {
            RouteId = "route2",
            ClusterId = "cluster2",
            Match = new RouteMatch { Path = "/" }
        };

        var proxyConfig = new YarpInMemoryConfigProvider(new List<RouteConfig> { route1, route2 }, new List<ClusterConfig> { cluster1, cluster2 });

        var configChangeListenerCounter = new ConfigChangeListenerCounter();
        var fakeConfigChangeListener = new FakeConfigChangeListener();

        var services = CreateServices(new[] { configProviderA, configProviderB, }, new[] { proxyConfig }, new IFirewallConfigChangeListener[] { configChangeListenerCounter, fakeConfigChangeListener });

        ProxyConfigManagerInitialLoadAsync(services);

        // Two empty config providers should load and apply successfully
        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(2, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.False(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A1", "B1" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.True(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Equal(new[] { "A1", "B1" }, fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Empty(fakeConfigChangeListener.FailedApplied);

        var firewall1 = new RouteFirewallConfig
        {
            RouteId = "route1",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = System.Net.HttpStatusCode.Forbidden,
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
            BlockedStatusCode = System.Net.HttpStatusCode.Forbidden,
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

        fakeConfigChangeListener.Reset();
        configChangeListenerCounter.Reset();

        // Updating one config provider should load and apply successfully
        configProviderA.Update(new List<RouteFirewallConfig>() { firewall1 }, "A2");

        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(2, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.False(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.True(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Empty(fakeConfigChangeListener.FailedApplied);

        fakeConfigChangeListener.Reset();
        configChangeListenerCounter.Reset();

        // Updating one config provider to return null should fail to load
        configProviderB.ShouldConfigLoadingFail = true;

        configProviderB.Update(new List<RouteFirewallConfig>() { firewall2 }, "B2");

        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(1, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(2, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.True(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.True(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Empty(fakeConfigChangeListener.FailedApplied);
    }

    [Fact]
    public void BuildConfig_CanBeNotifiedOfProxyConfigSuccessfulAndFailedUpdating()
    {
        const string TestAddress = "https://localhost:123/";

        var configProviderA = new OnDemandFailingInMemoryConfigProvider(new List<RouteFirewallConfig>(), "A1");
        var configProviderB = new OnDemandFailingInMemoryConfigProvider(new List<RouteFirewallConfig>(), "B1");

        var cluster1 = new ClusterConfig
        {
            ClusterId = "cluster1",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d1", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route1 = new RouteConfig
        {
            RouteId = "route1",
            ClusterId = "cluster1",
            Match = new RouteMatch { Path = "/" }
        };

        var cluster2 = new ClusterConfig
        {
            ClusterId = "cluster2",
            Destinations = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase)
            {
                { "d2", new DestinationConfig { Address = TestAddress } }
            }
        };
        var route2 = new RouteConfig
        {
            RouteId = "route2",
            ClusterId = "cluster2",
            Match = new RouteMatch { Path = "/" }
        };

        var proxyConfig = new YarpInMemoryConfigProvider(new List<RouteConfig> { route1, route2 }, new List<ClusterConfig> { cluster1, cluster2 });

        var configChangeListenerCounter = new ConfigChangeListenerCounter();
        var fakeConfigChangeListener = new FakeConfigChangeListener();

        var services = CreateServices(new[] { configProviderA, configProviderB, }, new[] { proxyConfig }, new IFirewallConfigChangeListener[] { configChangeListenerCounter, fakeConfigChangeListener });

        ProxyConfigManagerInitialLoadAsync(services);

        // Two empty config providers should load and apply successfully
        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(2, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.False(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A1", "B1" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.True(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Equal(new[] { "A1", "B1" }, fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Empty(fakeConfigChangeListener.FailedApplied);

        var firewall1 = new RouteFirewallConfig
        {
            RouteId = "route1",
            Enabled = true,
            Mode = FirewallMode.Prevention,
            RedirectUri = "https://localhost:10000/blocked",
            BlockedStatusCode = System.Net.HttpStatusCode.Forbidden,
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
            // Missing RouteId here will be caught by validation
        };

        fakeConfigChangeListener.Reset();
        configChangeListenerCounter.Reset();

        // Updating one config provider should load and apply successfully
        configProviderA.Update(new List<RouteFirewallConfig>() { firewall1 }, "A2");

        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(2, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.False(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.True(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Equal(new[] { "A2", "B1" }, fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Empty(fakeConfigChangeListener.FailedApplied);

        fakeConfigChangeListener.Reset();
        configChangeListenerCounter.Reset();

        // Updating one config provider with invalid config should fail to apply
        configProviderB.Update(new List<RouteFirewallConfig>() { firewall2 }, "B2");

        Assert.Equal(2, configChangeListenerCounter.NumberOfLoadedConfigurations);
        Assert.Equal(0, configChangeListenerCounter.NumberOfFailedConfigurationLoads);
        Assert.Equal(0, configChangeListenerCounter.NumberOfAppliedConfigurations);
        Assert.Equal(2, configChangeListenerCounter.NumberOfFailedConfigurationApplications);

        Assert.False(fakeConfigChangeListener.DidAtLeastOneErrorOccurWhileLoading);
        Assert.Equal(new[] { "A2", "B2" }, fakeConfigChangeListener.EventuallyLoaded);
        Assert.False(fakeConfigChangeListener.HasApplyingSucceeded);
        Assert.Empty(fakeConfigChangeListener.SuccessfullyApplied);
        Assert.Equal(new[] { "A2", "B2" }, fakeConfigChangeListener.FailedApplied);
    }

    private static void ProxyConfigManagerInitialLoadAsync(IServiceProvider services)
    {
        // This hack is needed to initialise Yarp's ProxyConfigurationManager
        var proxyLookup = services.GetRequiredService<IProxyStateLookup>();
        var proxyConfigManagerInitMethod = proxyLookup.GetType()
            .GetRuntimeMethods()
            .First(m => m.Name == "InitialLoadAsync");
        proxyConfigManagerInitMethod.Invoke(proxyLookup, null);
    }

    private class InMemoryConfig : IFirewallConfig
    {
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        public InMemoryConfig(IReadOnlyList<RouteFirewallConfig> firewalls, string revisionId)
        {
            RouteFirewalls = firewalls;
            RevisionId = revisionId;
            ChangeToken = new CancellationChangeToken(_cts.Token);
        }

        public string RevisionId { get; }

        public IReadOnlyList<RouteFirewallConfig> RouteFirewalls { get; }

        public IDictionary<Type, object> ConfigurationExtensions { get; }

        public IChangeToken ChangeToken { get; }


        internal void SignalChange()
        {
            _cts.Cancel();
        }
    }

    private class OnDemandFailingInMemoryConfigProvider : IFirewallConfigProvider
    {
        private volatile InMemoryConfig _config;

        public OnDemandFailingInMemoryConfigProvider(InMemoryConfig config)
        {
            _config = config;
        }

        public OnDemandFailingInMemoryConfigProvider(IReadOnlyList<RouteFirewallConfig> firewalls, string revisionId)
            : this(new InMemoryConfig(firewalls, revisionId))
        {
        }

        public bool ShouldConfigLoadingFail { get; set; }

        public IFirewallConfig GetConfig()
        {
            if (ShouldConfigLoadingFail)
            {
                return null;
            }

            return _config;
        }

        public void Update(InMemoryConfig config)
        {
            var oldConfig = Interlocked.Exchange(ref _config, config);
            oldConfig.SignalChange();
        }

        public void Update(IReadOnlyList<RouteFirewallConfig> firewalls, string revisionId)
        {
            Update(new InMemoryConfig(firewalls, revisionId));
        }
    }

    private class FakeConfigChangeListener : IFirewallConfigChangeListener
    {
        public bool? HasApplyingSucceeded { get; private set; }
        public bool DidAtLeastOneErrorOccurWhileLoading { get; private set; }
        public string[] EventuallyLoaded;
        public string[] SuccessfullyApplied;
        public string[] FailedApplied;

        public FakeConfigChangeListener()
        {
            Reset();
        }

        public void Reset()
        {
            DidAtLeastOneErrorOccurWhileLoading = false;
            HasApplyingSucceeded = null;
            EventuallyLoaded = Array.Empty<string>();
            SuccessfullyApplied = Array.Empty<string>();
            FailedApplied = Array.Empty<string>();
        }

        public void ConfigurationApplied(IReadOnlyList<IFirewallConfig> firewallConfigs)
        {
            HasApplyingSucceeded = true;
            SuccessfullyApplied = firewallConfigs.Select(c => c.RevisionId).ToArray();
        }

        public void ConfigurationApplyingFailed(IReadOnlyList<IFirewallConfig> firewallConfigs, Exception ex)
        {
            HasApplyingSucceeded = false;
            FailedApplied = firewallConfigs.Select(c => c.RevisionId).ToArray();
        }

        public void ConfigurationLoaded(IReadOnlyList<IFirewallConfig> firewallConfigs)
        {
            EventuallyLoaded = firewallConfigs.Select(c => c.RevisionId).ToArray();
        }

        public void ConfigurationLoadingFailed(IFirewallConfigProvider provider, Exception ex)
        {
            DidAtLeastOneErrorOccurWhileLoading = true;
        }
    }

    private class ConfigChangeListenerCounter : IFirewallConfigChangeListener
    {
        public int NumberOfLoadedConfigurations { get; private set; }
        public int NumberOfFailedConfigurationLoads { get; private set; }
        public int NumberOfAppliedConfigurations { get; private set; }
        public int NumberOfFailedConfigurationApplications { get; private set; }

        public ConfigChangeListenerCounter()
        {
            Reset();
        }

        public void Reset()
        {
            NumberOfLoadedConfigurations = 0;
            NumberOfFailedConfigurationLoads = 0;
            NumberOfAppliedConfigurations = 0;
            NumberOfFailedConfigurationApplications = 0;
        }

        public void ConfigurationApplied(IReadOnlyList<IFirewallConfig> firewallConfigs)
        {
            NumberOfAppliedConfigurations += firewallConfigs.Count;
        }

        public void ConfigurationApplyingFailed(IReadOnlyList<IFirewallConfig> firewallConfigs, Exception ex)
        {
            NumberOfFailedConfigurationApplications += firewallConfigs.Count;
        }

        public void ConfigurationLoaded(IReadOnlyList<IFirewallConfig> firewallConfigs)
        {
            NumberOfLoadedConfigurations += firewallConfigs.Count;
        }

        public void ConfigurationLoadingFailed(IFirewallConfigProvider provider, Exception ex)
        {
            NumberOfFailedConfigurationLoads++;
        }
    }
}

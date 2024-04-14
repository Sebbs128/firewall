using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators.Builder;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.Extensions.Firewall.Management;

internal sealed class FirewallConfigManager : IFirewallStateLookup, IDisposable
{
    private static readonly IReadOnlyDictionary<string, RouteConfig> _emptyRouteDictionary = new ReadOnlyDictionary<string, RouteConfig>(new Dictionary<string, RouteConfig>());

    private readonly IFirewallConfigProvider[] _providers;
    private readonly IFirewallConfigChangeListener[] _configChangeListeners;
    private readonly IProxyStateLookup _proxyStateLookup;
    private readonly IFirewallConfigValidator _configValidator;
    private readonly IEvaluatorBuilder _evaluatorBuilder;
    private readonly ILogger<FirewallConfigManager> _logger;
    private readonly ConcurrentDictionary<string, RouteState> _routes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, RouteFirewallState> _firewalls = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConfigState[] _configs;
    private CancellationTokenSource _configChangeSource = new();

    public FirewallConfigManager(
        IEnumerable<IFirewallConfigProvider> providers,
        IEnumerable<IFirewallConfigChangeListener> configChangeListeners,
        IProxyStateLookup proxyStateLookup,
        IFirewallConfigValidator configValidator,
        IEvaluatorBuilder evaluatorBuilder,
        ILogger<FirewallConfigManager> logger)
    {
        _providers = providers?.ToArray() ?? throw new ArgumentNullException(nameof(providers));
        _configChangeListeners = configChangeListeners?.ToArray() ?? throw new ArgumentNullException(nameof(configChangeListeners));
        _proxyStateLookup = proxyStateLookup ?? throw new ArgumentNullException(nameof(proxyStateLookup));
        _configValidator = configValidator ?? throw new ArgumentNullException(nameof(configValidator));
        _evaluatorBuilder = evaluatorBuilder ?? throw new ArgumentNullException(nameof(evaluatorBuilder));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (_providers.Length == 0)
        {
            throw new ArgumentException($"At least one {nameof(IFirewallConfigProvider)} is required.", nameof(providers));
        }

        _configs = new ConfigState[_providers.Length];
    }

    private static IReadOnlyList<IFirewallConfig> ExtractListOfFirewallConfigs(IEnumerable<ConfigState> configStates)
    {
        return configStates.Select(state => state.LatestConfig).ToList().AsReadOnly();
    }

    internal async Task InitialLoadAsync()
    {
        // Trigger the first load immediately, and throw if it fails.
        // This is intended to crash the app so it doesn't try listening for further changes.
        try
        {
            var firewalls = new List<RouteFirewallConfig>();

            var resolvedConfigs = new List<(int Index, IFirewallConfigProvider Provider, ValueTask<IFirewallConfig> Config)>(_providers.Length);

            for (var i = 0; i < _providers.Length; i++)
            {
                var provider = _providers[i];

                var config = LoadConfig(provider);
                _configs[i] = new ConfigState(provider, config);
                firewalls.AddRange(config.RouteFirewalls ?? Array.Empty<RouteFirewallConfig>());
            }

            var firewallConfigs = ExtractListOfFirewallConfigs(_configs);

            foreach (var configChangeListener in _configChangeListeners)
            {
                configChangeListener.ConfigurationLoaded(firewallConfigs);
            }

            await ApplyConfigAsync(firewalls);

            foreach (var configChangeListener in _configChangeListeners)
            {
                configChangeListener.ConfigurationApplied(firewallConfigs);
            }

            ListenForConfigChanges();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Unable to load or apply the firewall configuration.", ex);
        }
    }

    private async Task ReloadConfigAsync()
    {
        _configChangeSource.Dispose();

        var sourcesChanged = false;
        var firewalls = new List<RouteFirewallConfig>();

        foreach (var instance in _configs)
        {
            try
            {
                if (instance.LatestConfig.ChangeToken.HasChanged)
                {
                    var config = LoadConfig(instance.Provider);
                    instance.LatestConfig = config;
                    instance.LoadFailed = false;
                    sourcesChanged = true;
                }
            }
            catch (Exception ex)
            {
                instance.LoadFailed = true;
                Log.ErrorReloadingConfig(_logger, ex);

                foreach (var configChangeListener in _configChangeListeners)
                {
                    configChangeListener.ConfigurationLoadingFailed(instance.Provider, ex);
                }
            }

            // If we didn't/couldn't get a new config then re-use the last one.
            firewalls.AddRange(instance.LatestConfig.RouteFirewalls ?? Array.Empty<RouteFirewallConfig>());
        }

        var firewallConfigs = ExtractListOfFirewallConfigs(_configs);
        foreach (var configChangeListener in _configChangeListeners)
        {
            configChangeListener.ConfigurationLoaded(firewallConfigs);
        }

        try
        {
            // Only reload if at least one provider changed.
            if (sourcesChanged)
            {
                var hasChanged = await ApplyConfigAsync(firewalls);
            }

            foreach (var configChangeListener in _configChangeListeners)
            {
                configChangeListener.ConfigurationApplied(firewallConfigs);
            }
        }
        catch (Exception ex)
        {
            Log.ErrorApplyingConfig(_logger, ex);

            foreach (var configChangeListener in _configChangeListeners)
            {
                configChangeListener.ConfigurationApplyingFailed(firewallConfigs, ex);
            }
        }

        ListenForConfigChanges();
    }

    private void ValidateConfigProperties(IFirewallConfig config)
    {
        if (config is null)
        {
            throw new InvalidOperationException($"{nameof(IFirewallConfigProvider.GetConfig)} returned a null value.");
        }
        if (config.ChangeToken is null)
        {
            throw new InvalidOperationException($"{nameof(IFirewallConfig.ChangeToken)} has a null value.");
        }
    }

    private IFirewallConfig LoadConfig(IFirewallConfigProvider provider)
    {
        var config = provider.GetConfig();
        ValidateConfigProperties(config);
        return config;
    }

    private void ListenForConfigChanges()
    {
        // use a central change token to avoid overlap between different sources.
        var source = new CancellationTokenSource();
        _configChangeSource = source;
        var poll = false;

        foreach (var configState in _configs)
        {
            if (configState.LoadFailed)
            {
                // We can't register for change notifications if the last load failed.
                poll = true;
                continue;
            }

            configState.CallbackCleanup?.Dispose();
            var token = configState.LatestConfig.ChangeToken;
            if (token.ActiveChangeCallbacks)
            {
                configState.CallbackCleanup = token.RegisterChangeCallback(SignalChange, source);
            }
            else
            {
                poll = true;
            }
        }

        if (poll)
        {
            source.CancelAfter(TimeSpan.FromMinutes(5));
        }

        // Don't register until we're done hooking everything up to avoid cancellation races.
        source.Token.Register(ReloadConfig, this);

        static void SignalChange(object? obj)
        {
            var token = (CancellationTokenSource)obj!;
            try
            {
                token.Cancel();
            }
            // don't throw if the source was already disposed
            catch (ObjectDisposedException) { }
        }

        static void ReloadConfig(object? state)
        {
            var manager = (FirewallConfigManager)state!;
            _ = manager.ReloadConfigAsync();
        }
    }

    private async Task<bool> ApplyConfigAsync(IReadOnlyList<RouteFirewallConfig> firewalls)
    {
        var (configuredFirewalls, firewallErrors) = await VerifyFirewallsAsync(firewalls);

        if (firewallErrors.Count > 0)
        {
            throw new AggregateException("The firewall config is invalid.", firewallErrors);
        }

        // Update routes first because firewalls need to reference them
        UpdateRuntimeRoutes(new List<RouteModel>(_proxyStateLookup.GetRoutes()));
        return UpdateRuntimeFirewalls(configuredFirewalls);
    }

    private async Task<(IList<RouteFirewallConfig>, IList<Exception>)> VerifyFirewallsAsync(IReadOnlyList<RouteFirewallConfig> firewalls)
    {
        if (firewalls is null)
        {
            return (Array.Empty<RouteFirewallConfig>(), Array.Empty<Exception>());
        }

        var seenRouteIds = new HashSet<string>(firewalls.Count, StringComparer.OrdinalIgnoreCase);
        var configuredFirewalls = new List<RouteFirewallConfig>(firewalls.Count);
        var errors = new List<Exception>();

        foreach (var f in firewalls)
        {
            try
            {
                if (seenRouteIds.Contains(f.RouteId))
                {
                    errors.Add(new ArgumentException($"Duplicate route firewall '{f.RouteId}'"));
                    continue;
                }

                // Don't modify the original
                var firewall = f;

                var firewallErrors = await _configValidator.ValidateFirewall(firewall);
                if (firewallErrors.Count > 0)
                {
                    errors.AddRange(firewallErrors);
                    continue;
                }

                seenRouteIds.Add(firewall.RouteId);
                configuredFirewalls.Add(firewall);
            }
            catch (Exception ex)
            {
                errors.Add(new Exception($"An exception was thrown from the configuration callbacks for route firewall '{f.RouteId}'.", ex));
                continue;
            }
        }

        if (errors.Count > 0)
        {
            return (Array.Empty<RouteFirewallConfig>(), errors);
        }

        return (configuredFirewalls, errors);
    }

    private void UpdateRuntimeRoutes(IList<RouteModel> incomingRoutes)
    {
        var desiredRoutes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var incomingRoute in incomingRoutes)
        {
            var routeId = incomingRoute.Config.RouteId;
            var added = desiredRoutes.Add(routeId);
            Debug.Assert(added);

            if (_routes.TryGetValue(routeId, out var currentRoute))
            {
                var currentRouteModel = currentRoute.Model;

                if (currentRouteModel.HasConfigChanged(incomingRoute.Config))
                {
                    currentRoute.Revision++;
                    Log.RouteChanged(_logger, currentRoute.RouteId);
                }
            }
            else
            {
                var newRouteState = new RouteState(routeId)
                {
                    Model = incomingRoute
                };
                newRouteState.Revision++;

                added = _routes.TryAdd(newRouteState.RouteId, newRouteState);
                Debug.Assert(added);
                Log.RouteAdded(_logger, newRouteState.RouteId);
            }
        }

        // Directly enumerate the ConcurrentDictionary to limit locking and copying
        foreach (var existingRoutePair in _routes)
        {
            var existingRoute = existingRoutePair.Value;
            if (!desiredRoutes.Contains(existingRoute.RouteId))
            {
                Log.RouteRemoved(_logger, existingRoute.RouteId);
                var removed = _routes.TryRemove(existingRoute.RouteId, out var _);
                Debug.Assert(removed);
            }
        }
    }

    private bool UpdateRuntimeFirewalls(IList<RouteFirewallConfig> incomingFirewalls)
    {
        var desiredFirewalls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var changed = false;

        foreach (var incomingFirewall in incomingFirewalls)
        {
            desiredFirewalls.Add(incomingFirewall!.RouteId!);

            var routeId = incomingFirewall.RouteId ?? string.Empty;
            _routes.TryGetValue(routeId, out var route);

            if (_firewalls.TryGetValue(routeId, out var currentFirewall))
            {
                if (currentFirewall.Model.HasConfigChanged(incomingFirewall, route, currentFirewall.RouteRevision))
                {
                    var newModel = BuildFirewallModel(incomingFirewall, route);
                    currentFirewall.Model = newModel;
                    currentFirewall.RouteRevision = route?.Revision;
                    changed = true;
                    Log.RouteFirewallChanged(_logger, currentFirewall.RouteId);
                }
            }
            else
            {
                var newModel = BuildFirewallModel(incomingFirewall, route);
                var newState = new RouteFirewallState(incomingFirewall!.RouteId!)
                {
                    Model = newModel,
                    RouteRevision = route?.Revision,
                };
                var added = _firewalls.TryAdd(newState.RouteId, newState);
                Debug.Assert(added);
                changed = true;
                Log.RouteFirewallAdded(_logger, newState.RouteId);
            }
        }

        // Directly enumerate the ConcurrentDictionary to limit locking and copying
        foreach (var existingRoutePair in _firewalls)
        {
            var routeId = existingRoutePair.Value.RouteId;
            if (!desiredFirewalls.Contains(routeId))
            {
                Log.RouteFirewallRemoved(_logger, routeId);
                var removed = _firewalls.TryRemove(routeId, out _);
                Debug.Assert(removed);
                changed = true;
            }
        }

        return changed;
    }

    private RouteFirewallModel BuildFirewallModel(RouteFirewallConfig source, RouteState? route)
    {
        var evaluator = _evaluatorBuilder.Build(source, route?.Model?.Config);
        return new RouteFirewallModel(source, route, evaluator);
    }

    public bool TryGetRouteFirewall(string id, [NotNullWhen(true)] out RouteFirewallModel? firewall)
    {
        if (_firewalls.TryGetValue(id, out var firewallState))
        {
            firewall = firewallState.Model;
            return true;
        }

        firewall = null;
        return false;
    }

    public IEnumerable<RouteFirewallModel> GetRouteFirewalls()
    {
        foreach (var (_, firewall) in _firewalls)
        {
            yield return firewall.Model;
        }
    }

    public void Dispose()
    {
        _configChangeSource.Dispose();
        foreach (var instance in _configs)
        {
            instance?.CallbackCleanup?.Dispose();
        }
    }

    private class ConfigState
    {
        public ConfigState(IFirewallConfigProvider provider, IFirewallConfig config)
        {
            Provider = provider;
            LatestConfig = config;
        }

        public IFirewallConfigProvider Provider { get; }

        public IFirewallConfig LatestConfig { get; set; }

        public bool LoadFailed { get; set; }

        public IDisposable? CallbackCleanup { get; set; }
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _firewallAdded = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteFirewallAdded,
            "Route Firewall '{routeId}' has been added.");

        private static readonly Action<ILogger, string, Exception?> _firewallChanged = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteFirewallChanged,
            "Route Firewall '{routeId}' has changed.");

        private static readonly Action<ILogger, string, Exception?> _firewallRemoved = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteFirewallRemoved,
            "Route Firewall '{routeId}' has been removed.");

        private static readonly Action<ILogger, string, Exception?> _routeAdded = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteAdded,
            "Route '{routeId}' has been added.");

        private static readonly Action<ILogger, string, Exception?> _routeChanged = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteChanged,
            "Route '{routeId}' has changed.");

        private static readonly Action<ILogger, string, Exception?> _routeRemoved = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RouteRemoved,
            "Route '{routeId}' has been removed.");

        private static readonly Action<ILogger, Exception> _errorReloadingConfig = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ErrorReloadingConfig,
            "Failed to reload config. Unable to register for change notifications, polling for changes until successful.");

        private static readonly Action<ILogger, Exception> _errorApplyingConfig = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ErrorApplyingConfig,
            "Failed to apply the new config.");

        public static void RouteFirewallAdded(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _firewallAdded(logger, routeId, null);
        }

        public static void RouteFirewallChanged(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _firewallChanged(logger, routeId, null);
        }

        public static void RouteFirewallRemoved(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _firewallRemoved(logger, routeId, null);
        }

        public static void RouteAdded(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _routeAdded(logger, routeId, null);
        }

        public static void RouteChanged(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _routeChanged(logger, routeId, null);
        }

        public static void RouteRemoved(ILogger<FirewallConfigManager> logger, string routeId)
        {
            _routeRemoved(logger, routeId, null);
        }

        public static void ErrorReloadingConfig(ILogger<FirewallConfigManager> logger, Exception ex)
        {
            _errorReloadingConfig(logger, ex);
        }

        public static void ErrorApplyingConfig(ILogger<FirewallConfigManager> logger, Exception ex)
        {
            _errorApplyingConfig(logger, ex);
        }
    }
}

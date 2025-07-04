using MaxMind.Db;
using MaxMind.GeoIP2;

using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.GeoIP;
using Yarp.Extensions.Firewall.MaxMindGeoIP.Configuration;
using Yarp.Extensions.Firewall.MaxMindGeoIP.Utilities;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP;
internal sealed class GeoIPDatabaseProviderFactory : IGeoIPDatabaseProviderFactory, IDisposable
{
    private readonly IFirewallConfigProvider[] _providers;
    private readonly object _lock = new object();
    private readonly ILogger<GeoIPDatabaseProviderFactory> _logger;
    private ConfigState[]? _configs;
    private GeoIPDatabaseProvider? _databaseReader;
    private CancellationTokenSource _configChangeSource = new();
    private CancellationTokenSource _providerDisposeSource = new();

    public GeoIPDatabaseProviderFactory(IEnumerable<IFirewallConfigProvider> providers, ILogger<GeoIPDatabaseProviderFactory> logger)
    {
        _providers = providers?.ToArray() ?? throw new ArgumentNullException(nameof(providers));

        _logger = logger;
    }

    public IGeoIPDatabaseProvider GetCurrent()
    {
        // intent is to lazily create the DatabaseReader as
        //   a) the path may not initially exist
        //   b) a GeoIP rule may not be configured
        // first call of GetCurrent() should always be from
        //  GeoIPConditionFactory's Validate() method, rather than any Evaluator
        //  so the extra cost by doing it this way shouldn't be as impactful
        if (_configs is null)
        {
            lock (_lock)
            {
                if (_configs is null)
                {
                    _configs = new ConfigState[_providers.Length];
                    InitialLoad();
                }
            }
        }

        return _databaseReader!;
    }

    internal void InitialLoad()
    {
        for (var i = 0; i < _providers.Length; i++)
        {
            var provider = _providers[i];
            _configs![i] = new ConfigState(provider, provider.GetConfig());
        }

        BuildDatabaseReader();

        ListenForConfigChanges();
    }

    internal void Reload()
    {
        _configChangeSource.Dispose();

        var sourcesChanged = false;

        foreach (var instance in _configs!)
        {
            try
            {
                if (instance.LatestConfig.ChangeToken.HasChanged)
                {
                    var config = instance.Provider.GetConfig();
                    instance.LatestConfig = config;
                    instance.LoadFailed = false;
                    sourcesChanged = true;
                }
            }
            catch (Exception)
            {
                instance.LoadFailed = true;
                throw; // re-throw exception as validation is expecting it
            }
        }

        if (sourcesChanged)
            BuildDatabaseReader();

        ListenForConfigChanges();
    }

    private void BuildDatabaseReader()
    {
        // first valid (file exists and is a Country database) will be used
        foreach (var config in _configs!)
        {
            var settings = config.LatestConfig.GetExtendedConfiguration<GeoIPDatabaseConfig>();
            var dbpath = settings?.GeoIPDatabasePath;
            if (string.IsNullOrWhiteSpace(dbpath))
                continue;

            if (File.Exists(dbpath))
            {
                var dbReader = new DatabaseReader(dbpath);
                // ensure it is a Country database
                if (!dbReader.Metadata.DatabaseType.Contains("Country"))
                    throw new InvalidDataException($"A GeoIP2/GeoLite2 Country database was expected, but the database type is {dbReader.Metadata.DatabaseType}");

                // GeoIP2.DatabaseReader should be reused, as creation of it is expensive
                // we also need to ensure that it's not disposed while an evaluator is using it
                var oldDisposeSource = _providerDisposeSource;
                _providerDisposeSource = new();

                _databaseReader = new(dbReader, _providerDisposeSource.Token);
                Log.DatabaseOpened(_logger, dbReader.Metadata, dbpath);

                oldDisposeSource.Cancel();
                oldDisposeSource.Dispose();

                return;
            }
        }
    }

    private void ListenForConfigChanges()
    {
        // use a central change token to avoid overlap between different sources
        var source = new CancellationTokenSource();
        _configChangeSource = source;
        var poll = false;

        var callbacks = new List<IDisposable>();

        foreach (var config in _configs!)
        {
            if (config.LoadFailed)
            {
                // can't register for change notifications if the last load failed.
                poll = true;
                continue;
            }

            var token = config.LatestConfig.ChangeToken;
            if (token.ActiveChangeCallbacks)
            {
                callbacks.Add(token.RegisterChangeCallback(SignalChange, source));
            }
            else
            {
                poll = true;
            }
        }

        if (poll)
            source.CancelAfter(TimeSpan.FromMinutes(5));

        source.Token.Register(ReloadConfig, this);

        static void SignalChange(object? obj)
        {
            var token = (CancellationTokenSource)obj!;
            try
            {
                token.Cancel();
            }
            catch (ObjectDisposedException) { }
        }

        static void ReloadConfig(object? state)
        {
            var factory = (GeoIPDatabaseProviderFactory)state!;
            factory.Reload();
        }
    }

    public void Dispose()
    {
        _configChangeSource.Dispose();
        _providerDisposeSource.Dispose();
        _databaseReader?.Dispose();

        if (_configs != null)
        {
            foreach (var instance in _configs)
            {
                instance?.CallbackCleanup?.Dispose();
            }
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
        private static readonly Action<ILogger, string, int, int, DateTime, string, Exception?> _databaseOpened = LoggerMessage.Define<string, int, int, DateTime, string>(
            LogLevel.Debug,
            EventIds.GeoIPDatabaseOpened,
            "GeoIP2 '{dbType}' database v{majorVersion}.{minorVersion} (Build {buildDate:yyyy-MM-dd}) was opened from '{path}'.");

        public static void DatabaseOpened(ILogger<GeoIPDatabaseProviderFactory> logger, Metadata metadata, string path)
        {
            _databaseOpened(logger, metadata.DatabaseType, metadata.BinaryFormatMajorVersion, metadata.BinaryFormatMinorVersion, metadata.BuildDate, path, null);
        }
    }
}

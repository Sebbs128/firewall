using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using System.Diagnostics.CodeAnalysis;
using System.Net;

using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Configuration.ConfigProvider;

internal sealed class ConfigurationConfigProvider : IFirewallConfigProvider, IDisposable
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<ConfigurationConfigProvider> _logger;
    private readonly object _lock = new();

    private ConfigurationSnapshot? _snapshot;
    private CancellationTokenSource? _changeToken;
    private bool _disposed;
    private IDisposable? _subscription;

    public ConfigurationConfigProvider(IConfiguration configuration, ILogger<ConfigurationConfigProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));
        ArgumentNullException.ThrowIfNull(logger, nameof(logger));

        _configuration = configuration;
        _logger = logger;
    }

    public IFirewallConfig GetConfig()
    {
        if (_snapshot is null)
        {
            _subscription = ChangeToken.OnChange(_configuration.GetReloadToken, UpdateSnapshot);
            UpdateSnapshot();
        }

        return _snapshot;
    }

    [MemberNotNull(nameof(_snapshot))]
    private void UpdateSnapshot()
    {
        // lock to prevent overlapping updates, particularly on startup
        lock (_lock)
        {
            Log.LoadData(_logger);
            ConfigurationSnapshot newSnapshot;
            try
            {
                newSnapshot = new ConfigurationSnapshot();

                newSnapshot.GeoIPDatabasePath = _configuration[nameof(IFirewallConfig.GeoIPDatabasePath)] ?? string.Empty;

                foreach (var section in _configuration.GetSection(nameof(IFirewallConfig.RouteFirewalls)).GetChildren())
                {
                    newSnapshot.RouteFirewalls.Add(CreateRouteFirewall(section));
                }
            }
            catch (Exception ex)
            {
                Log.ConfigurationDataConversionFailed(_logger, ex);

                if (_snapshot is null)
                {
                    throw;
                }

                return;
            }

            var oldToken = _changeToken;
            _changeToken = new CancellationTokenSource();
            newSnapshot.ChangeToken = new CancellationChangeToken(_changeToken.Token);
            _snapshot = newSnapshot;

            try
            {
                oldToken?.Cancel(throwOnFirstException: false);
            }
            catch (Exception ex)
            {
                Log.ErrorSignalingChange(_logger, ex);
            }
        }
    }

    private static RouteFirewallConfig CreateRouteFirewall(IConfigurationSection section)
    {
        return new RouteFirewallConfig
        {
            RouteId = section.Key,
            Enabled = section.ReadBool(nameof(RouteFirewallConfig.Enabled)) ?? true,
            Mode = section.ReadEnum<FirewallMode>(nameof(RouteFirewallConfig.Mode)) ?? FirewallMode.Detection,
            RedirectUri = section[nameof(RouteFirewallConfig.RedirectUri)],
            BlockedStatusCode = section.ReadEnum<HttpStatusCode>(nameof(RouteFirewallConfig.BlockedStatusCode)) ?? HttpStatusCode.Forbidden,
            Rules = CreateRules(section.GetSection(nameof(RouteFirewallConfig.Rules)))
        };
    }

    private static IReadOnlyList<RuleConfig> CreateRules(IConfigurationSection section)
    {
        if (section.GetChildren() is var children && !children.Any())
        {
            return new List<RuleConfig>();
        }

        return children.Select(data => CreateRule(data)).ToList();
    }

    private static RuleConfig CreateRule(IConfigurationSection section)
    {
        return new RuleConfig
        {
            RuleName = section.Key,
            Priority = section.ReadUInt32(nameof(RuleConfig.Priority)) ?? 0,
            Action = section.ReadEnum<MatchAction>(nameof(RuleConfig.Action)) ?? MatchAction.Log,
            Conditions = CreateConditions(section.GetSection(nameof(RuleConfig.Conditions))),
        };
    }

    private static IReadOnlyList<MatchCondition> CreateConditions(IConfigurationSection section)
    {
        if (section.GetChildren() is var children && !children.Any())
        {
            return new List<MatchCondition>();
        }

        return children.Select(data => CreateCondition(data)).ToList();
    }

    private static MatchCondition CreateCondition(IConfigurationSection section)
    {
        var matchType = section.ReadEnum<ConditionMatchType>(nameof(MatchCondition.MatchType));
        MatchCondition matchCondition = matchType switch
        {
            ConditionMatchType.String => CreateStringMatchCondition(section),
            ConditionMatchType.Size => CreateSizeMatchCondition(section),
            ConditionMatchType.IPAddress => CreateIPAddressMatchCondition(section),
            ConditionMatchType.GeoIP => CreateGeoIPMatchCondition(section),
            _ => throw new NotSupportedException()
        };
        matchCondition.Negate = section.ReadBool(nameof(MatchCondition.Negate)) ?? false;
        return matchCondition;
    }

    private static StringMatchCondition CreateStringMatchCondition(IConfigurationSection section)
    {
        return new StringMatchCondition
        {
            MatchVariable = section.ReadEnum<MatchVariable>(nameof(StringMatchCondition.MatchVariable)),
            Selector = section[nameof(StringMatchCondition.Selector)] ?? string.Empty,
            MatchValues = section.GetSection(nameof(StringMatchCondition.MatchValues)).ReadStringArray() ?? Array.Empty<string>(),
            Operator = section.ReadEnum<StringOperator>(nameof(StringMatchCondition.Operator)) ?? StringOperator.Any,
            Transforms = CreateTransforms(section.GetSection(nameof(StringMatchCondition.Transforms))),
        };
    }

    private static SizeMatchCondition CreateSizeMatchCondition(IConfigurationSection section)
    {
        return new SizeMatchCondition
        {
            MatchVariable = section.ReadEnum<MatchVariable>(nameof(SizeMatchCondition.MatchVariable)),
            Selector = section[nameof(SizeMatchCondition.Selector)] ?? string.Empty,
            MatchValue = section.ReadUInt32(nameof(SizeMatchCondition.MatchValue)) ?? 0,
            Operator = section.ReadEnum<NumberOperator>(nameof(SizeMatchCondition.Operator)) ?? NumberOperator.LessThan,
            Transforms = CreateTransforms(section.GetSection(nameof(SizeMatchCondition.Transforms))),
        };
    }

    private static IPAddressMatchCondition CreateIPAddressMatchCondition(IConfigurationSection section)
    {
        return new IPAddressMatchCondition
        {
            MatchVariable = section.ReadEnum<IPMatchVariable>(nameof(IPAddressMatchCondition.MatchVariable)),
            IPAddressOrRanges = section[nameof(IPAddressMatchCondition.IPAddressOrRanges)] ?? string.Empty,
        };
    }

    private static GeoIPMatchCondition CreateGeoIPMatchCondition(IConfigurationSection section)
    {
        return new GeoIPMatchCondition
        {
            MatchVariable = section.ReadEnum<IPMatchVariable>(nameof(GeoIPMatchCondition.MatchVariable)),
            MatchCountryValues = section.GetSection(nameof(GeoIPMatchCondition.MatchCountryValues)).ReadStringArray() ?? Array.Empty<string>(),
        };
    }

    private static IReadOnlyList<Transform> CreateTransforms(IConfigurationSection section)
    {
        if (section.GetChildren() is var children && !children.Any())
        {
            return new List<Transform>();
        }

        return children
            .Select(data => CreateTransform(data))
            .Where(v => v is not null)
            .Cast<Transform>()
            .ToList();
    }

    private static Transform? CreateTransform(IConfigurationSection section)
    {
        return Enum.Parse<Transform>(section.Value); // throws if value isn't a correct value
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _subscription?.Dispose();
            _changeToken?.Dispose();
            _disposed = true;
        }
    }

    // gives parent class access to LoggerMessage for high performance logging
    private static class Log
    {
        private static readonly Action<ILogger, Exception> _errorSignallingChange = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ErrorSignalingChange,
            "An exception was thrown from the change notification.");

        private static readonly Action<ILogger, Exception> _configurationDataConversionFailed = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ConfigurationDataConversionFailed,
            "Configuration data conversion failed.");

        private static readonly Action<ILogger, Exception?> _loadData = LoggerMessage.Define(
            LogLevel.Information,
            EventIds.LoadData,
            "Loading firewall data from config.");

        internal static void ConfigurationDataConversionFailed(ILogger<ConfigurationConfigProvider> logger, Exception ex)
        {
            _configurationDataConversionFailed(logger, ex);
        }

        internal static void ErrorSignalingChange(ILogger<ConfigurationConfigProvider> logger, Exception ex)
        {
            _errorSignallingChange(logger, ex);
        }

        internal static void LoadData(ILogger<ConfigurationConfigProvider> logger)
        {
            _loadData(logger, null);
        }
    }
}

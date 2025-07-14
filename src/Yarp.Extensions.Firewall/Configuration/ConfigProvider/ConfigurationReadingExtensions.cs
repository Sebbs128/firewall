using System.Globalization;

using Microsoft.Extensions.Configuration;

namespace Yarp.Extensions.Firewall.Configuration.ConfigProvider;

// from https://github.com/microsoft/reverse-proxy/blob/main/src/ReverseProxy/Configuration/ConfigProvider/ConfigurationReadingExtensions.cs
internal static class ConfigurationReadingExtensions
{
    internal static int? ReadInt32(this IConfiguration configuration, string name)
    {
        return configuration[name] is string value
            ? int.Parse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture)
            : null;
    }
    internal static uint? ReadUInt32(this IConfiguration configuration, string name)
    {
        return configuration[name] is string value
            ? uint.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture)
            : null;
    }

    internal static TEnum? ReadEnum<TEnum>(this IConfiguration configuration, string name) where TEnum : struct
    {
        return configuration[name] is string value
            ? Enum.Parse<TEnum>(value, ignoreCase: true)
            : null;
    }

    internal static bool? ReadBool(this IConfiguration configuration, string name)
    {
        return configuration[name] is string value
            ? bool.Parse(value)
            : null;
    }

    internal static uint[]? ReadUIntArray(this IConfigurationSection section)
    {
        if (section.GetChildren() is var children && !children.Any())
        {
            return null;
        }

        return [.. children.Select(s => uint.Parse(s.Value!, NumberStyles.None, CultureInfo.InvariantCulture))];
    }

    internal static string[]? ReadStringArray(this IConfigurationSection section)
    {
        if (section.GetChildren() is var children && !children.Any())
        {
            return null;
        }

        return [.. children.Select(s => s.Value!)];
    }
}

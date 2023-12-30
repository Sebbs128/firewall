using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.CompilerServices;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Utilities;

internal static class StringUtilities
{
    [return: NotNullIfNotNull(nameof(value))]
    public static string? ApplyTransform(string? value, Transform transform)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        return transform switch
        {
            Transform.Uppercase => value.ToUpperInvariant(),
            Transform.Lowercase => value.ToLowerInvariant(),
            Transform.Trim => value.Trim(),
            Transform.UrlEncode => WebUtility.UrlEncode(value),
            Transform.UrlDecode => UrlDecode(value),
            _ => value,
        };
    }

    private static string UrlDecode(string encodedValue)
    {
        do
        {
            encodedValue = WebUtility.UrlDecode(encodedValue);
        } while (ContainsUrlEncodedValue(encodedValue));

        return encodedValue;

        static bool ContainsUrlEncodedValue(string s)
        {
            int idx = s.IndexOf('%');
            return idx + 2 < s.Length && IsHexDigit(s[idx+1]) && IsHexDigit(s[idx+2]);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsHexDigit(char c) =>
#if NET6_0
        "0123456789ABCDEF".Contains(c, StringComparison.OrdinalIgnoreCase);
#else
        char.IsAsciiHexDigit(c);
#endif

    public static bool IsEndPartOfUrlEncoding(string bodyPart, out int lengthFromEnd)
    {
        (var result, var n) = bodyPart switch
        {
            { Length: 0 } => (false, 0),
            var s when s[^1] is '%' => (true, 1), // last character is %
            { Length: 1 } => (false, 0), // any other single-character string
            var s when s[^2] is '%' && IsHexDigit(s[^1]) => (true, 2), // second-last character is %, and last character is hex
            { Length: 2 } => (false, 0), // any other two-character string
            _ => (false, 0),
        };

        lengthFromEnd = n;
        return result;
    }
}

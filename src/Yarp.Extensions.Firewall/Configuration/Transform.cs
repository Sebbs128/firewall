namespace Yarp.Extensions.Firewall.Configuration;

/// <summary>
/// Transformations to apply before evaluating conditions.
/// </summary>
public enum Transform
{
    /// <summary>
    /// Convert content to upper-case.
    /// </summary>
    Uppercase,
    /// <summary>
    /// Convert content to lower-case.
    /// </summary>
    Lowercase,
    /// <summary>
    /// Trim leading and trailing whitespace from content.
    /// </summary>
    Trim,
    /// <summary>
    /// Decode special URL characters.
    /// </summary>
    UrlDecode,
    /// <summary>
    /// Encode special URL characters.
    /// </summary>
    UrlEncode
}

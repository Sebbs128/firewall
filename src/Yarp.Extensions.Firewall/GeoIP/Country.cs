namespace Yarp.Extensions.Firewall.GeoIP;

/// <summary>
/// Represents a country with its ISO code and name.
/// </summary>
/// <remarks>This record is commonly used to store and transfer information about a country,  including its ISO
/// 3166-1 alpha-2 code and its display name.</remarks>
/// <param name="IsoCode">The two-letter code for the country, as defined in ISO 3166-1 alpha-2</param>
/// <param name="Name">The name of the country</param>
public record Country(string? IsoCode, string? Name);

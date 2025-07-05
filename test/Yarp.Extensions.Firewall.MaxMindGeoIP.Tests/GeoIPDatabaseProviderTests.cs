using MaxMind.GeoIP2;

using Yarp.Extensions.Firewall.MaxMindGeoIP.Tests.Common;

namespace Yarp.Extensions.Firewall.MaxMindGeoIP.Tests;
public class GeoIPDatabaseProviderTests
{
    [Fact]
    public void Get_Works()
    {
        var dbReader = new DatabaseReader(TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));
        var tokenSource = new CancellationTokenSource();
        var provider = new GeoIPDatabaseProvider(dbReader, tokenSource.Token);

        Assert.NotNull(provider.Get());
    }

    [Fact]
    public void Disposes_OnlyOnceTokenSourceCancelled()
    {
        var dbReader = new DatabaseReader(TestResources.GetGeoIPDatabasePath("GeoLite2-Country.mmdb"));
        var tokenSource = new CancellationTokenSource();
        var provider = new GeoIPDatabaseProvider(dbReader, tokenSource.Token);

        Assert.NotNull(provider.Get());
        provider.Dispose();

        Assert.NotNull(provider.Get());
        tokenSource.Cancel();
        provider.Dispose();

        Assert.Throws<ObjectDisposedException>(() => provider.Get());
    }
}

using System.Net.Http.Headers;

using Yarp.Extensions.Firewall.FunctionalTests.Common;

namespace Yarp.Extensions.Firewall.FunctionalTests;

public abstract class FunctionalTestBase
{
    public virtual async Task<HttpResponseMessage> SendHttpRequest(
    Uri requestUri,
    HttpMethod? httpMethod = default,
    HttpContent? content = default,
    IDictionary<string, HeaderStringValues>? headers = default)
    {
        httpMethod ??= HttpMethod.Get;

        using var client = new HttpClient();
        using var request = new HttpRequestMessage(httpMethod, requestUri)
        {
            Content = content
        };
        if (headers is not null && headers.Count > 0)
        {
            foreach (var header in headers)
            {
                request.Headers.Add(header.Key, header.Value);
            }
        }

        return await client.SendAsync(request);
    }
}

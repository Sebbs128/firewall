using System.Net.Http.Headers;

using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Utilities;

public static class HttpRequestExtensions
{
    public static bool HasFileContent(this HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType))
        {
            return false;
        }

        // Matches multipart/form-data
        if (contentType!.MediaType!.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
        {
            if (request.Form.Files.Count > 0)
            {
                return true;
            }
        }

        return false;
    }
}

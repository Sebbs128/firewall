using System.Net.Http.Headers;

using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Utilities;

/// <summary>
/// Extension methods for fetching information from the current HttpRequest.
/// </summary>

public static class HttpRequestExtensions
{
    /// <summary>
    /// Checks if the current request contains a file upload.
    /// </summary>
    public static bool HasFileContent(this HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType))
        {
            return false;
        }

        // Matches multipart/form-data
        return contentType!.MediaType!.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase)
            && request.Form.Files.Count > 0;
    }
}

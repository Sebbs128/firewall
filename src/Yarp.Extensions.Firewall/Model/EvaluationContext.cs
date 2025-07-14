using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Encapsulates information about firewall rule evaluation of an individual HTTP request.
/// </summary>
/// <remarks>
/// Creates a new instance around the given <see cref="HttpContext"/>.
/// </remarks>
/// <param name="httpContext"></param>
public sealed class EvaluationContext(HttpContext httpContext)
{
    /// <summary>
    /// The HTTP request being evaluated.
    /// </summary>
    public HttpContext HttpContext { get; init; } = httpContext;

    /// <summary>
    /// Information about any condition matches.
    /// </summary>
    public IList<EvaluatorMatchValue> MatchedValues { get; } = [];
}

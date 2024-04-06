using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Model;

/// <summary>
/// Encapsulates information about firewall rule evaluation of an individual HTTP request.
/// </summary>
public sealed class EvaluationContext
{
    /// <summary>
    /// Creates a new instance around the given <see cref="HttpContext"/>.
    /// </summary>
    /// <param name="httpContext"></param>
    public EvaluationContext(HttpContext httpContext)
    {
        HttpContext = httpContext;
    }

    /// <summary>
    /// The HTTP request being evaluated.
    /// </summary>
    public HttpContext HttpContext { get; init; }

    /// <summary>
    /// Information about any condition matches.
    /// </summary>
    public IList<EvaluatorMatchValue> MatchedValues { get; } = [];
}

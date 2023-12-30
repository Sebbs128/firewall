using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Model;

public sealed class EvaluationContext
{
    public EvaluationContext(HttpContext httpContext)
    {
        HttpContext = httpContext;
    }

    public HttpContext HttpContext { get; init; }

    public IList<EvaluatorMatchValue> MatchedValues { get; } = new List<EvaluatorMatchValue>();
}

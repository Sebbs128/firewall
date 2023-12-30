using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public abstract class RequestBodyConditionEvaluator<TOperator> : ConditionEvaluator<TOperator> where TOperator : Enum
{
    protected RequestBodyConditionEvaluator(TOperator @operator, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate)
    {
        Transforms = transforms;
    }

    public IReadOnlyList<Transform> Transforms { get; }

    public override async ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // skip body evaluation on file uploads
        // we primarily rely on the underlying web server's max request size limiting to prevent expecially large requests
        // TODO: should we have a separate, smaller limit for non-file uploads?
        //   both ModSec and Azure WAF do
        //   https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits#limits
        //   one thing revealed by that page is (in detection mode only) Content-Length header is used and compared to max request size limit
        if (context.HttpContext.Request.HasFileContent())
        {
            // TODO: log that evaluation was skipped for a file upload
            return false;
        }

        context.HttpContext.Request.EnableBuffering();

        try
        {
            var isMatch = await EvaluateInternal(context, cancellationToken);

            //return Negate ? !isMatch : isMatch; // this is equivalent to a XOR, which is the ^ bool operator
            return Negate ^ isMatch;
        }
        finally
        {
            await context.HttpContext.Request.BodyReader.CompleteAsync();
        }
    }

    internal abstract Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken);
}

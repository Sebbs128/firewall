using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestBodyStringAnyEvaluator : RequestBodyConditionEvaluator<StringOperator>
{
    public RequestBodyStringAnyEvaluator(bool negate, IReadOnlyList<Transform> transforms, ILogger<RequestBodyStringAnyEvaluator> logger)
        : base(StringOperator.Any, negate, transforms, logger)
    {
    }

    internal override async Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        if (context.HttpContext.Request.BodyReader is not null)
        {
            var readResult = await context.HttpContext.Request.BodyReader.ReadAsync(cancellationToken);

            if (!readResult.IsCompleted || !readResult.Buffer.IsEmpty)
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: $"{MatchVariable.RequestBody}{ConditionMatchType.String}",
                    OperatorName: nameof(StringOperator.Any),
                    MatchVariableValue: "")); // TODO?
                return true;
            }
        }

        return false;
    }
}

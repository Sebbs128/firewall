using System.Text;

using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the request body for any content.
/// </summary>
/// <inheritdoc/>
public class RequestBodyStringAnyEvaluator(bool negate, IReadOnlyList<Transform> transforms, ILogger<RequestBodyStringAnyEvaluator> logger) : RequestBodyConditionEvaluator<StringOperator>(StringOperator.Any, negate, transforms, logger)
{
    internal override async Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        if (context.HttpContext.Request.BodyReader is not null)
        {
            var readResult = await context.HttpContext.Request.BodyReader.ReadAsync(cancellationToken);

            if (!readResult.IsCompleted || !readResult.Buffer.IsEmpty)
            {
                var bufferContent = Encoding.UTF8.GetString(readResult.Buffer);

                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: $"{MatchVariable.RequestBody}{ConditionMatchType.String}",
                    OperatorName: nameof(StringOperator.Any),
                    MatchVariableValue: StringUtilities.FromStart(bufferContent, 100)));
                return true;
            }
        }

        return false;
    }
}

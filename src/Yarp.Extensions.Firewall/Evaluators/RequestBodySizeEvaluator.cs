using System.Text;

using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestBodySizeEvaluator : RequestBodyConditionEvaluator<NumberOperator>
{
    public RequestBodySizeEvaluator(NumberOperator @operator, uint matchValue, bool negate, IReadOnlyList<Transform> transforms)
        : base(@operator, negate, RemoveCaseTransforms(transforms))
    {
        MatchValue = matchValue;


        _hasUrlDecodeTransform = Transforms.Contains(Transform.UrlDecode);

        (_orEqual, _resultWhenLimitExceeded) = Operator switch
        {
            NumberOperator.GreaterThan => (false, true),
            NumberOperator.GreaterThanOrEqual => (true, true),
            NumberOperator.LessThan => (false, false),
            NumberOperator.LessThanOrEqual => (true, false),
            _ => throw new InvalidOperationException(Operator.ToString()),
        };
    }

    // Lower and Upper transforms don't affect the string's length, so we can ignore them
    private static List<Transform> RemoveCaseTransforms(IReadOnlyList<Transform> transforms) => transforms
        .Where(t => t is not Transform.Uppercase or Transform.Lowercase)
        .ToList();

    private readonly bool _orEqual;
    private readonly bool _resultWhenLimitExceeded;
    private readonly bool _hasUrlDecodeTransform;

    public uint MatchValue { get; }

    internal override async Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        var isMatch = false;
        int sizeSoFar = 0;
        var bodyReader = context.HttpContext.Request.BodyReader;

        if (bodyReader is not null)
        {
            var firstRead = true;

            // transform and evaluate in chunks, adjusting for cut-off URL-encoded values
            while (true)
            {
                var readResult = await bodyReader.ReadAsync(cancellationToken);
                var buffer = readResult.Buffer;

                var bufferContent = Encoding.UTF8.GetString(readResult.Buffer);

                // when partial url encoding is found (and url decode transform is being used), just use up until that position
                // append each read. we must contrain to the _maxMatchLength so we can exit as soon as it's reached
                // so that we're not rechecking items in MatchValues, we could create a copy (whole list? just indexes?)
                //    and remove from that when length is exceeded (or doesn't match).
                //    easy way for us to leave as soon as MatchValues is exhausted
                if (_hasUrlDecodeTransform && StringUtilities.IsEndPartOfUrlEncoding(bufferContent, out var lengthFromEnd))
                {
                    buffer = buffer.Slice(0, lengthFromEnd);
                    bufferContent = bufferContent[..^lengthFromEnd];
                }
                var transformedChunk = bufferContent;

                // Trim transform only need to be done on the start and end of the content
                // so here, it is split: TrimStart on first read, and TrimEnd only if we reach the end of the body
                foreach (var transform in Transforms)
                {
                    if (transform is Transform.Trim)
                    {
                        if (firstRead)
                            transformedChunk = transformedChunk.TrimStart();
                        else if (readResult.IsCompleted || buffer.IsSingleSegment)
                            transformedChunk = transformedChunk.TrimEnd();

                        continue;
                    }

                    transformedChunk = StringUtilities.ApplyTransform(transformedChunk, transform);
                }

                firstRead = false;
                bodyReader.AdvanceTo(buffer.Start, buffer.End);
                sizeSoFar += transformedChunk.Length;

                if (sizeSoFar > MatchValue)
                {
                    isMatch = _resultWhenLimitExceeded;
                    break;
                }

                if (_orEqual && sizeSoFar == MatchValue)
                {
                    isMatch = true;
                    break;
                }

                if (readResult.IsCompleted || buffer.IsSingleSegment)
                {
                    isMatch = !_resultWhenLimitExceeded;
                    break;
                }
            }
        }

        if (isMatch)
        {
            context.MatchedValues.Add(new EvaluatorMatchValue(
                MatchVariableName: $"{MatchVariable.RequestBody}{ConditionMatchType.Size}",
                OperatorName: Operator.ToString(),
                MatchVariableValue: sizeSoFar.ToString()));
        }

        return isMatch;
    }

}

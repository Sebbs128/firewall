using System.Text;

using Microsoft.AspNetCore.Http;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

public class RequestBodyStringStartsWithEvaluator : RequestBodyConditionEvaluator<StringOperator>
{
    private readonly int _minMatchLength;
    private readonly int _maxMatchLength;
    private readonly bool _hasUrlDecodeTransform;

    public RequestBodyStringStartsWithEvaluator(IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms)
        : base(StringOperator.StartsWith, negate, transforms)
    {
        MatchValues = matchValues;

        _minMatchLength = MatchValues.Min(v => v.Length);
        _maxMatchLength = MatchValues.Max(v => v.Length);
        _hasUrlDecodeTransform = transforms.Contains(Transform.UrlDecode);
    }

    public IReadOnlyList<string> MatchValues { get; }

    internal override async Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        var bodyReader = context.HttpContext.Request.BodyReader;

        if (bodyReader is not null)
        {
            var discardedMatchValues = new bool[MatchValues.Count];
            var readSoFar = new StringBuilder();
            bool firstRead = true;
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
                readSoFar.Append(transformedChunk);

                string transformedBody = readSoFar.ToString();

                // only run checks for matches if enough has been read for the smallest MatchValue
                if (transformedBody.Length >= _minMatchLength)
                {
                    bool allDiscarded = true;
                    for (int i = 0; i < discardedMatchValues.Length; i++)
                    {
                        if (discardedMatchValues[i])
                            continue;

                        string matchValue = MatchValues[i];

                        // larger than currently read amount. don't check again
                        if (matchValue.Length > transformedBody.Length)
                        {
                            discardedMatchValues[i] = true;
                            continue;
                        }

                        allDiscarded = false;

                        var matchFoud = transformedBody.StartsWith(matchValue, StringComparison.Ordinal);

                        if (matchFoud)
                        {
                            // TODO: consider reading a little more from the body so MatchVariableValue has a little more context
                            // i.e. get as close to the 100 characters as possible
                            context.MatchedValues.Add(new EvaluatorMatchValue(
                                MatchVariableName: $"{MatchVariable.RequestBody}{ConditionMatchType.String}",
                                OperatorName: nameof(StringOperator.StartsWith),
                                MatchVariableValue: StringUtilities.FromStart(transformedBody, 100)));

                            return true;
                        }

                        discardedMatchValues[i] = true;
                    }

                    if (allDiscarded)
                        return false;
                }

                if (transformedBody.Length > _maxMatchLength)
                    return false;

                bodyReader.AdvanceTo(buffer.Start, buffer.End);

                if (readResult.IsCompleted || buffer.IsSingleSegment)
                    return false;
            }
        }
        return false;
    }
}

using System.Buffers;
using System.Text;

using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates if the request body ends with any given strings.
/// </summary>
public class RequestBodyStringEndsWithEvaluator : RequestBodyConditionEvaluator<StringOperator>
{
    private readonly int _maxReadLength;
    private readonly int _minWindowSize;

    /// <inheritdoc/>
    public RequestBodyStringEndsWithEvaluator(IReadOnlyList<string> matchValues, bool negate, IReadOnlyList<Transform> transforms, ILogger<RequestBodyStringEndsWithEvaluator> logger)
        : base(StringOperator.EndsWith, negate, transforms, logger)
    {
        MatchValues = matchValues;

        _maxReadLength = Math.Max(100, MatchValues.Max(v => v.Length));
        _minWindowSize = (transforms.Contains(Transform.UrlDecode) ? 6 : 2) * _maxReadLength;
    }

    /// <summary>
    /// Values to match against.
    /// </summary>
    public IReadOnlyList<string> MatchValues { get; }

    internal override async Task<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        var bodyReader = context.HttpContext.Request.BodyReader;

        if (bodyReader is not null)
        {
            // use a sliding window buffer at least twice the size of maxMatchLength
            // (the worst case if just checking buffer is being short of the match by one character,
            //   but sliding one byte at a time would be too inefficient)
            // Needs to be larger if UrlDecode transform is used - the window size should be another x3 larger just to hold its worst case
            // all sizing is being handled in the constructor
            var arr = ArrayPool<byte>.Shared.Rent(_minWindowSize);
            try
            {
                var window = new Memory<byte>(arr);

                var readResult = await bodyReader.ReadAsync(cancellationToken);
                do
                {
                    // slide window contents down to make room for new data
                    int bytesToCopy;

                    for (int i = 0; i < readResult.Buffer.Length; i += bytesToCopy)
                    {
                        bytesToCopy = (int)Math.Min(readResult.Buffer.Length - i, window.Length);
                        var buffer = readResult.Buffer.Slice(i, bytesToCopy);

                        window[bytesToCopy..].CopyTo(window);

                        buffer.CopyTo(window.Span[(window.Length - bytesToCopy)..]);
                    }

                    bodyReader.AdvanceTo(readResult.Buffer.Start, readResult.Buffer.End);
                    readResult = await bodyReader.ReadAsync(cancellationToken);
                }
                while (!(readResult.IsCompleted || readResult.Buffer.IsSingleSegment));

                var transformedChunk = Encoding.UTF8.GetString(window.Span.TrimStart((byte)0));

                foreach (var transform in Transforms)
                {
                    transformedChunk = StringUtilities.ApplyTransform(transformedChunk, transform);
                }

                foreach (var matchValue in MatchValues)
                {
                    var foundIndex = transformedChunk.LastIndexOf(matchValue, StringComparison.Ordinal);
                    if (foundIndex == transformedChunk.Length - matchValue.Length)
                    {
                        context.MatchedValues.Add(new EvaluatorMatchValue(
                            MatchVariableName: $"{MatchVariable.RequestBody}{ConditionMatchType.String}",
                            OperatorName: nameof(StringOperator.EndsWith),
                            MatchVariableValue: StringUtilities.FromEnd(transformedChunk, 100)));

                        return true;
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(arr, clearArray: true);
            }
        }
        return false;
    }
}

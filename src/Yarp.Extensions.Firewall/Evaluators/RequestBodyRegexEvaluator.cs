using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Model;
using Yarp.Extensions.Firewall.Utilities;

namespace Yarp.Extensions.Firewall.Evaluators;

/// <summary>
/// Evaluates the request body against a regular expression.
/// </summary>
public class RequestBodyRegexEvaluator : RegexConditionEvaluator
{
    private readonly ILogger<RequestBodyRegexEvaluator> _logger;

    /// <inheritdoc/>
    public RequestBodyRegexEvaluator(IReadOnlyList<string> matchPatterns, bool negate, IReadOnlyList<Transform> transforms, ILogger<RequestBodyRegexEvaluator> logger)
        : base(matchPatterns, negate)
    {
        Transforms = transforms;
        _logger = logger;
    }

    /// <summary>
    /// Limits time taken to evaluate a regular expression.
    /// </summary>
    protected override TimeSpan RegexMatchTimeout { get; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Transformations to apply before evaluating.
    /// </summary>
    public IReadOnlyList<Transform> Transforms { get; }

    /// <inheritdoc/>
    public override async ValueTask<bool> Evaluate(EvaluationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // skip body evaluation on file uploads
        // we primarily rely on the underlying web server's max request size limiting to prevent expecially large requests
        // TODO: should we have a separate, smaller limit for non-file uploads?
        //   both ModSec and Azure WAF do
        //   https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits#limits
        if (context.HttpContext.Request.HasFileContent())
        {
            Log.FileContentSkipped(_logger, "RequestBodyRegex", context.HttpContext.Request.GetDisplayUrl());
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

    internal async ValueTask<bool> EvaluateInternal(EvaluationContext context, CancellationToken cancellationToken)
    {
        context.HttpContext.Request.EnableBuffering();
        var bodyReader = context.HttpContext.Request.BodyReader;

        if (bodyReader is not null)
        {
            var readSoFar = new StringBuilder();
            try
            {
                // read the whole body before doing transforms and checking regex patterns
                // - saves some cycles because we then only do them once, at the expense of memory
                // - regex could return false positives if we don't read everything
                //   - eg. regex is checking for un-closed parentheses
                var readResult = await bodyReader.ReadAsync(cancellationToken);
                do
                {
                    var buffer = readResult.Buffer;

                    readSoFar.Append(Encoding.UTF8.GetString(readResult.Buffer));

                    bodyReader.AdvanceTo(buffer.Start, buffer.End);
                    readResult = await bodyReader.ReadAsync(cancellationToken);
                }
                while (!(readResult.IsCompleted || readResult.Buffer.IsSingleSegment));
            }
            finally
            {
                // ensure Pipereader is marked complete
                await bodyReader.CompleteAsync();
            }

            var transformedBody = readSoFar.ToString();

            foreach (var transform in Transforms)
            {
                transformedBody = StringUtilities.ApplyTransform(transformedBody, transform);
            }

            if (MatchesAnyPatterns(transformedBody, out var matchValue))
            {
                context.MatchedValues.Add(new EvaluatorMatchValue(
                    MatchVariableName: "RequestBody",
                    OperatorName: nameof(StringOperator.Regex),
                    MatchVariableValue: matchValue[..Math.Min(100, matchValue.Length)]));

                return true;
            }
        }
        return false;
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, string, Exception?> _fileContentSkipped = LoggerMessage.Define<string, string>(
            LogLevel.Information,
            EventIds.FileContentSkipped,
            "{name} skipped evaluation of file content for {requestUri}.");

        public static void FileContentSkipped(ILogger<RequestBodyRegexEvaluator> logger, string evaluatorName, string requestUri)
        {
            _fileContentSkipped(logger, evaluatorName, requestUri, null);
        }
    }
}

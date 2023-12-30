using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.Extensions.Firewall.CoreRuleSet.Settings;

public enum RuleEngineState
{
    /// <summary>
    /// Indicates the RuleEngine should process rules
    /// </summary>
    On,
    /// <summary>
    /// Indicates the RuleEngine should not process rules
    /// </summary>
    Off,
    /// <summary>
    /// Indicates the RuleEngine should process rules, but never execute any disruptive actions
    /// </summary>
    DetectionOnly
}

public enum BodyAccessState
{
    /// <summary>
    /// Indicates Request/Response bodies are to be buffered
    /// </summary>
    On,
    /// <summary>
    /// Indicates Request/Response bodies are not to be buffered
    /// </summary>
    Off
}

public enum Variables
{
    /// <summary>
    /// A collection meaning all arguments (including POST payload) - both name and value.
    /// </summary>
    /// <remarks>
    /// For only the query string or body arguments, use ArgsGet or ArgsPost.
    /// Reference Manual allows specific ("ARGS:name" or "ARGS:regex"), exclusions ("!ARGS:name"), counting ("&ARGS")
    /// </remarks>
    Args,
    /// <summary>
    /// The combined size (in bytes) of all request parameters (excluding files).
    /// </summary>
    ArgsCombinedSize,
    /// <summary>
    /// A collection of all query string arguments - both name and value.
    /// </summary>
    ArgsGet,
    /// <summary>
    /// A collection of all query string argument names.
    /// </summary>
    ArgsGetNames,
    /// <summary>
    /// A collection of all request parameter names.
    /// </summary>
    ArgsNames,
    /// <summary>
    /// A collection of all POST body arguments - both name and value.
    /// </summary>
    ArgsPost,
    /// <summary>
    /// A colllection of all POST body argument names.
    /// </summary>
    ArgsPostNames,
    /// <summary>
    /// The authentication method used to validate a user.
    /// </summary>
    AuthType,
    /// <summary>
    /// Number of milliseconds elapsed since the beginning of the current transaction.
    /// </summary>
    Duration,
    /// <summary>
    /// A collection of environment variables set by a rule (via setenv) or some other module/middleware
    /// </summary>
    Env,
    /// <summary>
    /// A collection of original file names (as they were named on the remote user's file system).
    /// </summary>
    /// <remarks>
    /// Only available on inspected multipart/form-data requests (and files were extracted from the request body)
    /// </remarks>
    Files,
    /// <summary>
    /// The total size (in bytes) of the files transported in the request body.
    /// </summary>
    /// <remarks>
    /// Only available on inspected multipart/form-data requests
    /// </remarks>
    FilesCombinedSize,
    /// <summary>
    /// A collection of form fields that were used for file upload.
    /// </summary>
    /// <remarks>
    /// Only available on inspected multipart/form-data requests
    /// </remarks>
    FileNames,
    /// <summary>
    /// The complete request - Request line, request headers, and request body (if any).
    /// </summary>
    FullRequest,
    /// <summary>
    /// The amount of bytes that FullRequest may use.
    /// </summary>
    FullRequestLength,
    /// <summary>
    /// A collection of individual file sizes.
    /// </summary>
    /// <remarks>
    /// Useful for implementing a size limitation on individual uploaded files.
    /// Only available on inspected multipart/form-data requests
    /// </remarks>
    FileSizes,
    /// <summary>
    /// A collection of temporary files' names on disk.
    /// </summary>
    /// <remarks>
    /// Useful when used with @inspectFile.
    /// The executed script can use the provided filename to open the file and examine the contents.
    /// Only available on inspected multipart/form-data requests
    /// </remarks>
    FileTempNames,
    /// <summary>
    /// A key-value set where value is the content of the uploaded file.
    /// </summary>
    /// <remarks>
    /// Useful when used with @fuzzyhash
    /// Should use SecUploadKeepFiles set to "On" to have this collection filled.
    /// </remarks>
    FileTempContent,
    /// <summary>
    /// A collection of geographical fields populated by the results of the last 
    ///  @geoLookup operator on an IP address or hostname
    /// </summary>
    /// <remarks>
    /// Fields:
    ///  COUNTRY_CODE: Two character country code (eg. US, GB, etc)
    ///  COUNTRY_CODE3: Up to three character country code
    ///  COUNTRY_NAME: The full country name
    ///  COUNTRY_CONTINENT: The two character continent the country is located in (eg. EU)
    ///  REGION: The two character region. For US, this is state; for Canada, province, etc
    ///  CITY: The city name, if supported by the database
    ///  POSTAL_CODE: The postal code, if supported by the database
    ///  LATITUDE The latitude, if supported by the database
    ///  LONGITUDE: The longitude, if supported by the database
    ///  DMA_CODE: The metropolitan area code, if supported by the database (US only)
    ///  AREA_CODE: The phone system area code (US only)
    /// </remarks>
    Geo,
    /// <summary>
    /// The highest severity of any rules that have matched so far.
    /// </summary>
    /// <remarks>
    /// Severities are numeric values, so can be used with comparison operators such as @lt.
    /// Higher severities have a lower numeric value. A value of 255 indicates that no severity has been set.
    /// </remarks>
    HighestSeverity,
    /// <summary>
    /// Indicates when the request body size is above the setting configured by SecRequestBodyLimit
    /// </summary>
    InboundDataError,
    /// <summary>
    /// The value of the most-recent matched variable
    /// </summary>
    MatchedVar,
    /// <summary>
    /// A collection of all matches
    /// </summary>
    MatchedVars,
    /// <summary>
    /// The full name of the variable that was matched against.
    /// </summary>
    MatchedVarName,
    /// <summary>
    /// A collection containing the full name of all variables that have been matched against.
    /// </summary>
    MatchedVarNames,
    /// <summary>
    /// The ModSecurity build number.
    /// </summary>
    /// <remarks>
    /// Intended to be used to check the build number prior to using a feature that is available only in a certain build.
    /// </remarks>
    ModSecBuild,
    /// <summary>
    /// Indicates a multi-part requets uses mixed line terminators.
    /// </summary>
    MultipartCrlfLfLines,
    /// <summary>
    /// Contains the multipart data from the FILENAME field.
    /// </summary>
    MultipartFilename,
    /// <summary>
    /// Contains the multipart data from the NAME field.
    /// </summary>
    MultipartName,
    /// <summary>
    /// Collection of all part headers found within the request body with Content-Type multipart/form-data
    /// </summary>
    /// <remarks>
    /// The key of each item in the collection is the name of the part in which it was found,
    /// while the value is the entire part-header line including both the part-header name and the part-header value.
    /// </remarks>
    MultipartPartHeaders,
    /// <summary>
    /// Indicates when any of the is also set
    /// - RequestBodyProcessorError
    /// - MultipartBoundaryQuoted
    /// - MultipartBoundaryWhitespace
    /// - MultipartDataBefore
    /// - MultipartDataAfter
    /// - MultipartHeaderFolding
    /// - MultipartLfLine
    /// - MultipartMissingSemicolon
    /// - MultipartInvalidQuoting
    /// - MultipartInvalidHeaderFolding
    /// - MultipartFileLimitExceeded
    /// </summary>
    MultipartStrictError,
    /// <summary>
    /// Indicates possible evasion attempt by identifying lines that begin with '--'
    /// but are followed by characters such that it is not a match the boundary.
    /// </summary>
    MultipartUnmatchedBoundary,
    /// <summary>
    /// Indicates the response body size is above the setting configured by SecResponseBodyLimit
    /// </summary>
    OutboundDataError,
    /// <summary>
    /// Contains the request URI information that precedes any '?' character.
    /// </summary>
    PathInfo,
    /// <summary>
    /// Contains the query string part of a request URI.
    /// </summary>
    QueryString,
    /// <summary>
    /// Contains the IP address of the remote client.
    /// </summary>
    RemoteAddress,
    /// <summary>
    /// Synonym for RemoteAddress
    /// </summary>
    RemoteHost,
    /// <summary>
    /// Contains the source port that the client used when initiating the connection
    /// </summary>
    RemotePort,
    /// <summary>
    /// The username associated with the transaction, if successfully extracted from the 'Authorization' request header.
    /// </summary>
    RemoteUser,
    /// <summary>
    /// Indicates the request body processors failed to do their work.
    /// </summary>
    RequestBodyError,
    /// <summary>
    /// Contains a text message containing additional information when RequestBodyError is set.
    /// </summary>
    RequestBodyErrorMessage,
    /// <summary>
    /// Contains the name of the currently used request body processor.
    /// </summary>
    RequestBodyProcessor,
    /// <summary>
    /// Contains just the filename part of RequestFilename
    /// </summary>
    RequestBaseName,
    /// <summary>
    /// Contains the raw request body, if the UrlEncoded request body processor was used or forced.
    /// </summary>
    RequestBody,
    /// <summary>
    /// Contains the number of bytes read from a request body.
    /// </summary>
    RequestBodyLength,
    /// <summary>
    /// Collection of the values all request cookies.
    /// </summary>
    RequestCookies,
    /// <summary>
    /// Collection of the names of all request cookies.
    /// </summary>
    RequestCookiesNames,
    /// <summary>
    /// Contains the relative request URL without the query string part
    /// </summary>
    RequestFilename,
    /// <summary>
    /// Collection of all the request headers, or selected headers if specified
    /// </summary>
    RequestHeaders,
    /// <summary>
    /// Collection of the names of all request headers.
    /// </summary>
    RequestHeadersNames,
    /// <summary>
    /// Contains the complete request line sent to the server, including HTTP method and version.
    /// </summary>
    RequestLine,
    /// <summary>
    /// Contains the request method used in the transaction.
    /// </summary>
    RequestMethod,
    /// <summary>
    /// Contains the request protocol version information.
    /// </summary>
    RequestProtocol,
    /// <summary>
    /// Contains the full request URL, including the query string data but not the domain name
    /// </summary>
    RequestUri,
    /// <summary>
    /// Contains the full request URL, including the query string data, and the domain name if it was provided.
    /// </summary>
    RequestUriRaw,
    /// <summary>
    /// Contains the data for the response body, but only when response body buffering is enabled.
    /// </summary>
    ResponeBody,
    /// <summary>
    /// Contains the response body length in bytes
    /// </summary>
    ResponseContentLength,
    /// <summary>
    /// Contains the response content type
    /// </summary>
    ResponseContentType,
    /// <summary>
    /// Collection of all the response headers, or selected headers if specified
    /// </summary>
    ResponseHeaders,
    /// <summary>
    /// Collection of the names of all response headers.
    /// </summary>
    ResponseHeadersNames,
    /// <summary>
    /// Contains the HTTP response protocol information
    /// </summary>
    ResponseProtocol,
    /// <summary>
    /// Contains the HTTP response status code
    /// </summary>
    ResponseStatus,
    /// <summary>
    /// Special collection that provides access to the id, rev, severity, logdata, 
    /// and msg fields of the rule that triggered the action.
    /// </summary>
    /// <remarks>
    /// Refers to only the same rule in which it resides.
    /// </remarks>
    Rule,
    /// <summary>
    /// Contains the IP address of the server.
    /// </summary>
    ServerAddress,
    /// <summary>
    /// Contains the transaction's hostname or IP address, taken from the request itself.
    /// </summary>
    ServerName,
    /// <summary>
    /// Contains the local port that the web server (or reverse proxy) is listening on.
    /// </summary>
    ServerPort,
    /// <summary>
    /// Collection that contains session information. Only available after setsid is executed.
    /// </summary>
    Session,
    /// <summary>
    /// Contains the value set with setsid.
    /// </summary>
    SessionId,
    /// <summary>
    /// Contains the full status line sent by the server, including HTTP request method and version information.
    /// </summary>
    StatusLine,
    /// <summary>
    /// Contains a formatted string representing the time (h:m:s)
    /// </summary>
    Time,
    /// <summary>
    /// Contains the current date (day of month)
    /// </summary>
    TimeDay,
    /// <summary>
    /// Contains the time in seconds since 1970
    /// </summary>
    TimeEpoch,
    /// <summary>
    /// Contains the current hour value (0-23)
    /// </summary>
    TimeHour,
    /// <summary>
    /// Contains the current minute value (0-59)
    /// </summary>
    TimeMinute,
    /// <summary>
    /// Contains the current month value (0-11)
    /// </summary>
    TimeMonth,
    /// <summary>
    /// Contains the current second value (0-59)
    /// </summary>
    TimeSecond,
    /// <summary>
    /// Contains the current weekday value (1-7, Monday is 1)
    /// </summary>
    TimeWeekDay,
    /// <summary>
    /// Contains the current year value
    /// </summary>
    TimeYear,
    /// <summary>
    /// Collection that contains pieces of data for the transaction
    /// </summary>
    Tx,
    /// <summary>
    /// Contains a unique identifier for the transaction
    /// </summary>
    /// <remarks>
    /// ModSec v3 implementation is a millisecond timestamp, '.', then a random six-digit number
    /// </remarks>
    UniqueId,
    /// <summary>
    /// Created when an invalid URL encoding is encountered during parsing of a query string,
    /// or during the parsing of an application/x-www-form-urlencoded request body
    /// </summary>
    UrlEncodedError,
    /// <summary>
    /// Contains the value set with setuid
    /// </summary>
    UserId,
    /// <summary>
    /// Contains the current application name, as set with SecWebAppId
    /// </summary>
    WebAppId,
}

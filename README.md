# Firewall Middleware for YARP

[YARP ("Yet Another Reverse Proxy")](https://github.com/microsoft/reverse-proxy) is a reverse proxy toolkit for ASP.NET Core. This project extends YARP's functionality by adding firewall capabilities.

Being an extension to YARP, it follows much of the conventions in the YARP project, both in terms of solution and class structure. This also means that it can be configured in the same way as YARP; it supports configuration files, as well as a configuration API for programmatic, in-process configuration.

This project is currently in an early stage (⚠️ not production ready ⚠️), so I would love and greatly appreciate any contributions, reviews, and suggestions. Please see the [TODO](#todo) section below for an informal roadmap or list of things to be done.

- [Custom Rules](#custom-rules)
  - [Route Firewall](#route-firewall)
    - [Firewall Rules](#firewall-rules)
      - [Rule Conditions](#rule-conditions)
        - [IP Address Evaluators](#ip-address-evaluators)
        - [Size Evaluators](#size-evaluators)
        - [String Evaluators](#string-evaluators)
        - [Transforms](#transforms)
  - [Example Configuration](#example-configuration)

## Custom Rules

At present, YARP.Extensions.Firewall contains just a custom rule engine. The custom rule engine is heavily influenced by Azure WAF (found as part of Application Gateway and Front Door).

### Route Firewall

Firewalls with custom rules are configured per route (matching on the `RouteId` configured in YARP). Each route's firewall has a few basic settings

- `RouteId` - the name of the route, as configured in YARP
- `Enabled` - Enable (or disable)
- `Mode` - how the firewall should operate; `Detection` (log only), or `Prevention` (enforce rules)
- `BlockedStatusCode` - HTTP Status Code to return when a request is denied
- `RedirectUri` - URL to return when a request is redirected
- `Rules` - the set of custom rules for this

#### Firewall Rules

Custom Rules are configured as sets of conditions, and are executed according to their given priority; all conditions in a rule must match the request for the rule to be enforced with the specified action (ie. there is an implicit `AND` between all conditions in a rule). If all of a rule's conditions match the request, no other rules are evaluated. If no rules match, the request is implicitly allowed to continue to the YARP middleware.

- `RuleName` - the name or description given to the rule
- `Priority` - a number indicating what priority the rule should be given. `0` is highest priority
- `Action` - the action that should be taken when all conditions
  - `Allow` - the request is explicitly allowed to continue
  - `Block` - the request is denied and cannot continue; the firewall's `BlockedStatusCode` is returned to the client
  - `Log` - the request is logged, and allowed to continue
  - `Redirect` - a Redirect response is returned to the client, with the location set to the firewall's `RedirectUri`
- `Conditions` - the set of conditions that define this rule

##### Rule Conditions

A number of conditions are supported, with different configuration options depending on the property of the request being evaluated. All conditions have the below options

- `MatchType` - the type of value that will be evaluated
  - `Size` - the length of a request property will be evaluated
  - `String` - evaluation depends on a particular value in one of the request's properties
  - `IPAddress` - match on a given list or range of IP addresses
- `Negate` - the evaluation result will be inverted; ie. if a match was not found, the condition will return `true` (and vice versa)

###### IP Address Evaluators

When evaluating an `IPAddress` `MatchType`, either the client's socket address or the perceived remote address can be used for the match. That value will be evaluated against the given IP address, list of IP addresses, or CIDR range.

- `MatchVariable` - the property to retrieve the request's IP address from
  - `SocketAddress` - use the IP address from the actual connection; if the request was previously proxied, this might not be the actual client's address but rather the address of the proxy
  - `RemoteAddress` - the perceived client's address; at present, this will be the first valid value from the `X-Forwarded-For` header, falling back to the socket address if none was found
- `IPAddressOrRanges` - the IP address(es) to evaluate against, and accepts both IPv4 and IPv6 addresses. This may be either a single IP address, a comma-separated list of IP address, or a CIDR range

###### Size Evaluators

When `MatchType` is `Size`, evaluation is performed by comparing the configured `MatchValue` to the length of the configured request property. Some request properties require an additional `Selector` that specifies an additional key. A series of [transformations](#transforms) can be done on the value prior to the evaluation itself as well.

- `MatchVariable` - the request property to be evaluated. Valid values are
  - `RequestMethod` - the HTTP Method for the request (`GET`, `POST`, `HEAD` etc)
  - `QueryParam` - evaluate the length of the query parameter given by `Selector`
  - `PostArgs` - evaluate the length of the HTTP Form POST parameter given by `Selector`
  - `RequestPath` - evaluates the length of the relative URI, including the entire query string
  - `RequestHeader` - evaluate the length of the particular request header given by `Selector`
  - `RequestBody` - evaluate the length of the entire request body
  - `Cookie` - evaluate the size of the particular request cookie given by `Selector`
- `Operator` - the type of comparison to use against `MatchValue` after transformations are applied
  - `LessThan`
  - `GreaterThan`
  - `LessThanOrEqual`
  - `GreaterThanOrEqual`
- `Selector` - a key indicating which `Cookie`, `RequestHeader`, `PostArgs`, or `QueryParam` value to use, if it existed in the request
- `MatchValue` - the value to be compared against
- `Transforms` - a list of transformations to be applied, in order

###### String Evaluators

A `MatchType` of `String` will evaluate request properties against a list of values to determine a match. Like the `Size` evaluators, an additional key specified by `Selector` is required for some request properties, and [transformations](#transforms) can be applied before the value is evaluated.

- `MatchVariable` - the request property to be evaluated. Valid values are
  - `RequestMethod` - the HTTP Method for the request (`GET`, `POST`, `HEAD` etc)
  - `QueryParam` - the query parameter given by `Selector`
  - `PostArgs` - the HTTP Form POST parameter given by `Selector`
  - `RequestPath` - the relative URI, including the entire query string
  - `RequestHeader` - the particular request header given by `Selector`
  - `RequestBody` - the entire request body
  - `Cookie` - the particular request cookie given by `Selector`
- `Operator` - the type of case-sensitive string comparison to use for evaluation after transformations are applied
  - `Any` - the property contains any value
  - `Equals` - the property exactly equals one of the `MatchValues`
  - `Contains` - the property contains any of the `MatchValues`
  - `StartsWith` - the property starts with one of the `MatchValues`
  - `EndsWith` - the property ends with one of the `MatchValues`
  - `Regex` - the property matches one of the regular expression patterns given in `MatchValues`
- `Selector` - a key indicating which `Cookie`, `RequestHeader`, `PostArgs`, or `QueryParam` value to use, if it existed in the request
- `MatchValues` - a list of string values to be compared against
- `Transforms` - a list of transformations to be applied, in order

###### Transforms

Tranformations can be applied to the request values for `Size` and `String` evaluators prior to any comparisons to do things like changing the case, trimming whitespace, or applying URL decoding/encoding. `Tranforms` are applied in the order given in the condition configuration.

- `Uppercase` - convert the request value to upper-case
- `Lowercase` - convert the request value to lower-case
- `Trim` - remove any whitespace characters from the start and end of the value
- `UrlDecode` - convert any URL-encoded characters. This also accounts for repeat encodings, a common bypass technique
- `UrlEncode` - convert any special characters to their URL-encoded representation

(Case transformations don't affect `Size` evaluations, and are automatically ignored in that case.)

### Example Configuration

Below is an example of what this configuration looks like ([as used in `ConfigurationConfigProviderTests`](/test/Yarp.Extensions.Firewall.Tests/Configuration/ConfigProvider/ConfigurationConfigProviderTests.cs))

```json
{
    "RouteFirewalls": {
        "routeA": {
            "Enabled": true,
            "Mode": "Prevention",
            "RedirectUri": "https://localhost:10000/blocked",
            "BlockedStatusCode": "Forbidden",
            "Rules": {
                "stringAndSize": {
                    "Priority": 10,
                    "Action": "Block",
                    "Conditions": [
                        {
                            "MatchType": "String",
                            "Operator": "Contains",
                            "MatchVariable": "QueryParam",
                            "Selector": "a",
                            "MatchValues": [ "1" ],
                            "Transforms": [
                                "Trim",
                                "UrlDecode",
                                "Uppercase"
                            ]
                        },
                        {
                            "MatchType": "Size",
                            "Operator": "GreaterThanOrEqual",
                            "MatchVariable": "Cookie",
                            "Selector": "b",
                            "MatchValue": 100
                        }
                    ]
                },
                "ipAddress1": {
                    "Priority": 11,
                    "Action": "Allow",
                    "Conditions": [
                        {
                            "MatchType": "IPAddress",
                            "IPAddressOrRanges": "2001::abcd",
                            "MatchVariable": "SocketAddress"
                        }
                    ]
                }
            }
        },
        "routeB": {
            "Enabled": true,
            "Mode": "Detection",
            "RedirectUri": "https://localhost:20000/blocked.html",
            "BlockedStatusCode": "NotFound",
            "Rules": {
                "ipAddress2": {
                    "Priority": 5,
                    "Action": "Allow",
                        "Conditions": [
                        {
                            "MatchType": "IPAddress",
                            "IPAddressOrRanges": "192.168.0.0/16",
                            "MatchVariable": "RemoteAddress"
                        }
                    ]
                }
            }
        }
    }
}
```

# TODO

This is just the start of what I want to accomplish with this project. There are many more features I would like to add, and things to clean up. I'm keen to have discussions on any and all of these. In no particular order

- Publish the library to Nuget via CI/CD
  - preferably via Azure Pipelines, and possibly making use of [dotnet-arcade](https://github.com/dotnet/arcade)
- Publish a docs site
- clean up `// TODO`s
  - there's some pieces that either require a little more thought into how the firewall should behave, or values that should be logged
- more tests!
- expand, implement, and test telemetry
- New evaluators
  - Add a `GeoIP` `ConditionMatchType`
    - [ModSecurity Core Rule Set](https://coreruleset.org/) uses [MaxMind's GeoIP](https://dev.maxmind.com/geoip/geolocate-an-ip), which also happens to have a Nuget package ([MaxMind.GeoIP2](https://www.nuget.org/packages/MaxMind.GeoIP2/)). Integration should use the binary database, and support the user using either the paid (GeoIP2) or free (GeoLite2) license (which from what I can tell with a cursory look, doesn't differ in terms of code)
  - JSON-specific evaluators
    - this might look like using System.Text.Json with the `PipeReader`, or passing the body stream to `Utf8JsonReader` after enabling request buffering. Care needs to be taken with that second option to ensure YARP can still correctly forward the request contents
  - Size-count evaluators (eg. number of cookies/headers etc, by specific name or all)?
  - anything more applicable to web sockets? Azure WAF has nothing here as Front Door can't proxy web socket connections, but YARP can
- Consider adding firewall features that are more fundamental, if appropriate
  - There should be a balance here between what's appropriate to handle in a/this library, what ASP.NET Core or Kestrel can actually do (and if there's anything it's already doing or making irrelevant), and what can/could be handled elsewhere
    - protocol and similar enforcement (eg. request body matching content-length, duplicate headers)?
    - should anything that can be/is addressed by CRS should be left to CRS? (see below)
  - ASP.NET Core includes rate-limiting middleware (and rate limiting stuff should be left to it), but is it enough for DDoS protection, or should this library provide something for that? Either something at the connection (Kestral) level, or default configurations of the rate-limiting middleware?
- Integrate or port ModSec CRS
  - unsure what integrating looks like at the moment, given the distributables are intended for existing web servers.
    - there is also the [Coraza](https://github.com/corazawaf/coraza) library, which runs CRSv4
  - I envision a port looking like a combination of reading files from the CRS repo (regex files, and/or full .conf files), and source generators using those as input.
    - Porting has licensing implications due to ASLv2 ("if you alter, transform, or build upon this work, you may distribute the resulting work only under the same or similar license to this one"). Need to answer questions around what constitutes a "similar" license to ASLv2, if entire project needs to be licensed that way, or if just the specific code+library needs to be

# Contributing

I'm eager to accept contributions and suggestions in any form. Please feel free to open an issue, discussion, or PR, or to message me on here or Mastodon.

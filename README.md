# Firewall Middleware for YARP

[![Build Status](https://dev.azure.com/sebbs/Yarp.Extensions.Firewall/_apis/build/status%2FSebbs128.firewall?repoName=Sebbs128%2Ffirewall&branchName=main)](https://dev.azure.com/sebbs/Yarp.Extensions.Firewall/_build/latest?definitionId=16&repoName=Sebbs128%2Ffirewall&branchName=main)
[![CodeQL](https://github.com/Sebbs128/firewall/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Sebbs128/firewall/actions/workflows/github-code-scanning/codeql)
[![Nuget](https://img.shields.io/nuget/vpre/Sebbs.Yarp.Extensions.Firewall.svg?label=NuGet)](https://www.nuget.org/packages/Sebbs.Yarp.Extensions.Firewall)
[![Nuget](https://img.shields.io/nuget/vpre/Sebbs.Yarp.Extensions.Firewall.MaxMindGeoIP.svg?label=NuGet)](https://www.nuget.org/packages/Sebbs.Yarp.Extensions.Firewall.MaxMindGeoIP)

[YARP ("Yet Another Reverse Proxy")](https://github.com/microsoft/reverse-proxy) is a reverse proxy toolkit for ASP.NET Core. This project extends YARP's functionality by adding firewall capabilities.

Being an extension to YARP, this project follows much of the conventions in the YARP project, both in terms of solution and class structure. This also means that it can be configured in the same way as YARP; it supports configuration files, as well as a configuration API for programmatic, in-process configuration.

This project is currently in an early stage (⚠️ not production ready ⚠️), so I would love and greatly appreciate any contributions, reviews, and suggestions.

- [Custom Rules](#custom-rules)
  - [Route Firewall](#route-firewall)
    - [Firewall Rules](#firewall-rules)
      - [Rule Conditions](#rule-conditions)
        - [IP Address Evaluators](#ip-address-evaluators)
        - [Size Evaluators](#size-evaluators)
        - [String Evaluators](#string-evaluators)
        - [GeoIP Evaluators](#geoip-evaluators)
        - [Transforms](#transforms)
  - [Example Configuration](#example-configuration)

## Custom Rules

At present, Yarp.Extensions.Firewall contains just a custom rule engine. The custom rule engine is heavily influenced by Azure WAF (found as part of Application Gateway and Front Door).

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
  - `GeoIP` - match on a given country as determined by MaxMind GeoIP2 from the IP address
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

ASP.NET Core and Kestrel have [their own limits on request sizes](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/file-uploads#server-and-app-configuration), and in general these should be preferred over general/global `RequestBody` size rules.
Keep in mind that those limits will apply even if the firewall is in `Detection` mode, as they are inherent to the underlying server itself.

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

###### GeoIP Evaluators

The `GeoIP` value for `MatchType` will look up the client's country based on the IP address from either the socket address or remote address, and evaluate this against a list of supplied country names.

- `MatchVariable` - the property to retrieve the request's IP address from
  - `SocketAddress` - use the IP address from the actual connection; if the request was previously proxied, this might not be the actual client's address but rather the address of the proxy
  - `RemoteAddress` - the perceived client's address; at present, this will be the first valid value from the `X-Forwarded-For` header, falling back to the socket address if none was found
- `MatchCountryValues` - a list of country names (not case sensitive) to be evaluated against

The `Yarp.Extensions.Firewall.MaxMindGeoIP` library (in this solution) allows the use of a [MaxMind GeoIP2](https://dev.maxmind.com/geoip/updating-databases) Country database for this purpose.
This package must be referenced in your project, and added to the service collection via `IFirewallBuilder.AddMaxMindGeoIP()`.

The path to a GeoIP2 or GeoLite2 Country database is configured by a `GeoIPDatabaseConfig` object inside the firewall configuration (adjacent to `RouteFirewalls`), containing a `GeoIPDatabasePath` property. As with all other configuration values, the database path can be updated without requiring a restart, and as MaxMind frequently updates the databases (at time of writing, twice weekly) frequent updating is encouraged.

No database files are provided in this project, however one to suit your purpose (commercial, enterprise, or free) can be obtained from MaxMind. Note you will need the _Country_ database, and supplying any other type will fail to load the database and any configured GeoIP evaluators.

Alternatively, other GeoIP databases can be used by implementing the `IGeoIPDatabaseProviderFactory` and `IGeoIPDatabaseProvider` interfaces, and registering them with the service collection with `IFirewallBuilder.Services.TryAddSingleton<IGeoIPDatabaseProviderFactory, YourGeoIPDatabaseProviderFactory>()`. Configuration for your implementation can be done by implementing the `IFirewallConfigurationExtensionProvider` interface (or extneding the `FirewallConfigurationExtensionProvider` class), and registering it with the service collection with `IFirewallBuilder.AddConfigurationExtensionProvider<YourFirewallConfigurationExtensionProvider>()`.
(This also works for any other way you would like to extend the firewall functionality.)

###### Transforms

Tranformations can be applied to the request values for `Size` and `String` evaluators prior to any comparisons to do things like changing the case, trimming whitespace, or applying URL decoding/encoding. `Tranforms` are applied in the order given in the condition configuration.

- `Uppercase` - convert the request value to upper-case
- `Lowercase` - convert the request value to lower-case
- `Trim` - remove any whitespace characters from the start and end of the value
- `UrlDecode` - convert any URL-encoded characters. This also accounts for repeat encodings, a common bypass technique
- `UrlEncode` - convert any special characters to their URL-encoded representation

(Case transformations don't affect `Size` evaluations, and are automatically ignored in that case.)

### Example Configuration

Below is an example of what this configuration looks like ([as used in `ConfigurationConfigProviderTests`](/test/Yarp.Extensions.Firewall.Tests/Configuration/ConfigProvider/ConfigurationConfigProviderTests.cs)).
The parent section to `"RouteFirewalls"` must be passed to the `.LoadFromConfig()` extension method.
For example, place `"RouteFirewalls"` inside the section used for YARP (eg. `"ReverseProxy"`), alongside the `"Routes"` and `"Clusters"`.

```json
{
    // ...
    "ReverseProxy": {
        "Routes": {
            "routeA": { ... },
            "routeB": { ... }
        },
        "Clusters": { ... }

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
        },
        "GeoIPDatabaseConfig": {
            "GeoIPDatabasePath": "./path/to/GeoLite2-Country.mmdb"
        }
    }
}
```

# Contributing

I'm eager to accept contributions and suggestions in any form. Please feel free to open an issue, discussion, or PR, or to message me on here or Mastodon.

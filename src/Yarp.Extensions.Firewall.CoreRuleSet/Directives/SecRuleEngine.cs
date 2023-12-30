using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.Extensions.Firewall.CoreRuleSet.Settings;

namespace Yarp.Extensions.Firewall.CoreRuleSet.Directives;

// TODO:
//  there should maybe be an over-arching middleware that accepts the SecRuleEngine, SecRequest/ResponseBodyAccess, and the collection of SecRules
//
//  alternatively, SecRuleEngine, Request/ResponseBodyAccess, and the SecRule collection are just "config",
//  and the middleware processes them in order
//  - check RuleEngine state. if Off, skip everything below. if On, proceed. if DetectionOnly, proceed with a flag
//  - check RequestBodyAccess, and enable request body buffering if enabled (porting doc says required, but unsure if technically required in aspnetcore)
//  - check ResponseBodyAccess, and enable response body buffering if enabled (porting doc says required, but unsure if particularly possible or required in aspnetcore)
//  - iterate Rules and exclusions (need to implement SecRuleRemoveById/Tag, SecRuleUpdateTargetByTag/ActionById?)
//  context contains an Items dictionary, which we could use to track which rules were triggered and the action they want to take?
//   DetectionOnly flag wouldn't need to be passed to each rule
//   avoid risk of messing with the response or connection (in case of attempting to detect DoS) until after exclusions have been accounted for
public class SecRuleEngine
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<RuleSetSettings> _options;

    public SecRuleEngine(RequestDelegate next, IOptionsMonitor<RuleSetSettings> options)
    {
        _next = next;
        _options = options;
    }

    public Task InvokeAsync(HttpContext context)
    {
        return _next.Invoke(context);
    }
}

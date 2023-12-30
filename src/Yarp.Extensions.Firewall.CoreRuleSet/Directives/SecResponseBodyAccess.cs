using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.Extensions.Firewall.CoreRuleSet.Settings;

namespace Yarp.Extensions.Firewall.CoreRuleSet.Directives;

public class SecResponseBodyAccess
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<RuleSetSettings> _options;

    public SecResponseBodyAccess(RequestDelegate next, IOptionsMonitor<RuleSetSettings> options)
    {
        _next = next;
        _options = options;
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (_options.CurrentValue.ResponseBodyAccess == BodyAccessState.On)
        {
        }

        return _next.Invoke(context);
    }
}

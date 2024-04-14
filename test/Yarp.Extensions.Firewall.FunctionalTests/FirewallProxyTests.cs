using System.Net;

using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.FunctionalTests.Common;

namespace Yarp.Extensions.Firewall.FunctionalTests;

public class FirewallProxyTests : FunctionalTestBase
{
    [Fact]
    public async Task RequestMatchingBlockRule_RespondsWithForbiddenStatusCode()
    {
        var test = new TestEnvironment(context =>
        {
            Assert.Fail();
            return Task.CompletedTask;
        })
        {
            BlockedStatusCode = HttpStatusCode.Forbidden,
            FirewallRules = new List<RuleConfig>()
            {
                new RuleConfig()
                {
                    RuleName = "queryParam-a-contains-1",
                    Priority = 1,
                    Action = MatchAction.Block,
                    Conditions = new List<MatchCondition>()
                    {
                        new StringMatchCondition
                        {
                            Operator = StringOperator.Contains,
                            MatchVariable = MatchVariable.QueryParam,
                            Selector = "a",
                            MatchValues = new[] { "1" }
                        }
                    }
                }
            }
        };

        await test.Invoke(async baseUri =>
        {
            var uri = new UriBuilder(baseUri)
            {
                Query = "b=2&a=54123"
            };
            using var response = await SendHttpRequest(uri.Uri);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        });
    }
}

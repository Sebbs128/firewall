using Yarp.Extensions.Firewall.Configuration;
using Yarp.Extensions.Firewall.Evaluators.Builder;

namespace Yarp.Extensions.Firewall.Common.Tests;
public abstract class ConditionExtensionsTestsBase
{
    protected static ConditionBuilderContext CreateBuilderContext() => new();

    protected static ConditionBuilderContext ValidateAndBuild(IConditionFactory factory, MatchCondition matchCondition)
    {
        var validationContext = new EvaluatorValidationContext();

        Assert.True(factory.Validate(validationContext, matchCondition));
        Assert.Empty(validationContext.Errors);

        var builderContext = CreateBuilderContext();
        Assert.True(factory.Build(builderContext, matchCondition));

        return builderContext;
    }
}

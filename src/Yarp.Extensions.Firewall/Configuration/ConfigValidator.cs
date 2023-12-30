using Yarp.Extensions.Firewall.Evaluators.Builder;

namespace Yarp.Extensions.Firewall.Configuration;

internal sealed class ConfigValidator : IFirewallConfigValidator
{
    private readonly IEvaluatorBuilder _evaluatorBuilder;

    public ConfigValidator(IEvaluatorBuilder evaluatorBuilder)
    {
        ArgumentNullException.ThrowIfNull(evaluatorBuilder);
        _evaluatorBuilder = evaluatorBuilder;
    }


    public ValueTask<IList<Exception>> ValidateFirewall(RouteFirewallConfig firewall)
    {
        ArgumentNullException.ThrowIfNull(nameof(firewall));
        var errors = new List<Exception>();

        if (string.IsNullOrEmpty(firewall.RouteId))
        {
            errors.Add(new ArgumentException("Missing Route Id."));
        }

        errors.AddRange(_evaluatorBuilder.Validate(firewall));

        return ValueTask.FromResult((IList<Exception>)errors);
    }
}

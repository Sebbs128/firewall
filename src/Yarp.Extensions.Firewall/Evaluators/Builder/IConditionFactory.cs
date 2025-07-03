using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

/// <summary>
/// Validates and builds condition evaluators from the given parameters.
/// </summary>
public interface IConditionFactory
{
    /// <summary>
    /// Checks if the given condition values match a known condition evaluator, and if those values have any errors.
    /// </summary>
    /// <param name="context">The context to add any generated errors to.</param>
    /// <param name="condition">The condition values to validate.</param>
    /// <returns>True if this factory matches the given condition, otherwise false.</returns>
    public bool Validate(EvaluatorValidationContext context, MatchCondition condition);

    /// <summary>
    /// Checks if the given condition values match a known condition evaluator, and if so, generates a
    /// condition evaluator and adds it to the context. This can throw if the condition values are invalid.
    /// </summary>
    /// <param name="context">The context to add any generated condtion evaluators to.</param>
    /// <param name="condition">The condition values to use as input.</param>
    /// <returns>True if this factory matches the given condition, otherwise false.</returns>
    public bool Build(ConditionBuilderContext context, MatchCondition condition);
}

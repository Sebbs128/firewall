using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.Extensions.Firewall.Configuration;

namespace Yarp.Extensions.Firewall.Evaluators.Builder;

public static class ConditionHelper
{
    public static void TryCheckTransforms(EvaluatorValidationContext context, IReadOnlyList<Transform> transforms)
    {
        foreach (var transform in transforms)
        {
            switch (transform)
            {
                case Transform.Lowercase:
                case Transform.Uppercase:
                case Transform.UrlEncode:
                case Transform.UrlDecode:
                case Transform.Trim:
                    break;
                default:
                    context.Errors.Add(new ArgumentException($"Unexpected transform for SizeMatchCondition: {transform}"));
                    break;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.Extensions.Firewall.CoreRuleSet.Settings;

public class RuleSetSettings
{
    public RuleEngineState RuleEngineState { get; set; }

    public BodyAccessState RequestBodyAccess { get; set; }

    public BodyAccessState ResponseBodyAccess { get; set; }
}

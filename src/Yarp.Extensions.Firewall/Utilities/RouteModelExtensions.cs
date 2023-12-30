using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.Extensions.Firewall.Utilities;
internal static class RouteModelExtensions
{
    internal static bool HasConfigChanged(this RouteModel model, RouteConfig newConfig)
    {
        return !model.Config.Equals(newConfig);
    }
}

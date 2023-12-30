using Yarp.ReverseProxy.Model;

namespace Yarp.Extensions.Firewall.Model;

public class RouteState
{
    private volatile RouteModel _model = default!;

    public RouteState(string routeId)
    {
        RouteId = routeId ?? throw new ArgumentNullException(nameof(routeId));
    }

    public RouteState(string routeId, RouteModel model) : this(routeId)
    {
        Model = model ?? throw new ArgumentNullException(nameof(model));
    }

    public string RouteId { get; }

    public RouteModel Model
    {
        get => _model;
        internal set => _model = value ?? throw new ArgumentNullException(nameof(value));
    }

    internal int Revision { get; set; }
}

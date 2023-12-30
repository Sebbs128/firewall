using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Tests.Common;
public class RequestCookieCollection : Dictionary<string, string>, IRequestCookieCollection
{
    public RequestCookieCollection(IDictionary<string, string> dictionary) : base(dictionary)
    {
    }

    string? IRequestCookieCollection.this[string key] => base[key];

    ICollection<string> IRequestCookieCollection.Keys => base.Keys;
}

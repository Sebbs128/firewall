using Microsoft.AspNetCore.Http;

namespace Yarp.Extensions.Firewall.Tests.Common;
public class RequestCookieCollection(IDictionary<string, string> dictionary)
    : Dictionary<string, string>(dictionary), IRequestCookieCollection
{
    string IRequestCookieCollection.this[string key] => base[key];

    ICollection<string> IRequestCookieCollection.Keys => Keys;
}

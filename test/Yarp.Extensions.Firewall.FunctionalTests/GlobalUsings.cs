global using Xunit;

#if NET8_0_OR_GREATER
global using IPNetwork = System.Net.IPNetwork;
#else
global using IPNetwork = Yarp.Extensions.Firewall.Utilities.IPNetworkWrapper;
#endif

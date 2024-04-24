using Hecop_WFP;
using System;
using System.Collections.Generic;
using System.Net;

namespace HecopNet_Filter;

internal sealed class Condition
{
    public ActionType Action { get; set; }
    public ConditionType Type { get; set; }
    public InternetProtocolVersion Version { get; set; } = InternetProtocolVersion.All;
    public byte Weight { get; set; }

    public string Path { get; set; } = string.Empty;
    public Uri Uri { get; set; } = new("http://localhost/");
    public IReadOnlyCollection<IPAddress> Addresses { get; set; } = Array.Empty<IPAddress>();
    public IPNetwork2 Network { get; set; } = IPNetwork2.IANA_ABLK_RESERVED1;
    public ulong InterfaceIndex { get; set; }
    public ushort Port { get; set; }
}
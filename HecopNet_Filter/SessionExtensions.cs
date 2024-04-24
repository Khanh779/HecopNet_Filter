using Hecop_WFP;
using Hecop_WFP.Interop;
using HecopNet_Filter;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HecopNet_Filter;

[SupportedOSPlatform("windows6.0.6000")]
public static class SessionExtensions
{
    public static (Guid providerGuid, Guid subLayerGuid) RegisterKeys(this SafeHandle handle)
    {
        var providerGuid = handle.AddProvider("HecopNet_Filter",
            "HecopNet_Filter provider");
        var subLayerGuid = handle.AddSubLayer(providerGuid,
            "HecopNet_Filter filters",
            "Permissive and blocking filters");

        return (providerGuid, subLayerGuid);
    }

    public static void AddAppId(
        this SafeHandle handle,
        ActionType action,
        Guid providerKey,
        Guid subLayerKey,
        SafeFwpmHandle appId,
        byte weight)
    {
        foreach (var pair in Layers.All)
        {
            handle.AddAppId(
                action: action,
                providerKey,
                subLayerKey,
                pair.Value,
                appId,
                weight,
                "HecopNet_Filter",
                $"Permit unrestricted traffic ({pair.Key})");
        }
    }

    public static void AddAppId(
        this SafeHandle handle,
        ActionType action,
        Guid providerKey,
        Guid subLayerKey,
        string path,
        byte weight)
    {
        try
        {
            using var id = GetAppId(path);

            handle.AddAppId(action, providerKey, subLayerKey, id, weight);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException($"PermitAppId failed for path: {path}", exception);
        }
    }

    public static SafeFwpmHandle GetAppId(string fileName)
    {
        fileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
        if (!File.Exists(fileName))
        {
            throw new ArgumentException($"File is not exists: {fileName}");
        }

        return WfpMethods.GetAppIdFromFileName(fileName);
    }

    public static void BlockIpAddresses(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IReadOnlyCollection<IPAddress> addresses)
    {
        foreach (var pair in Layers.V4)
        {
            foreach (var address in addresses.Where(static address => address.AddressFamily == AddressFamily.InterNetwork))
            {
                handle.AddAddressV4(
                    ActionType.Block,
                    providerKey,
                    subLayerKey,
                    pair.Value,
                    weight,
                    new[] { address },
                    "HecopNet_Filter",
                    $"Block address - {address} ({pair.Key})");
            }
        }
    }

    public static void PermitIpAddresses(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IReadOnlyCollection<IPAddress> addresses)
    {
        foreach (var pair in Layers.V4)
        {
            handle.AddAddressV4(
                ActionType.Permit,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork),
                "HecopNet_Filter",
                $"Allow addresses ({pair.Key})");
        }
    }

    public static void PermitDns(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weightAllow,
        byte weightDeny,
        ICollection<IPAddress> addresses)
    {
        if (weightDeny >= weightAllow)
        {
            throw new ArgumentException("The allow weight must be greater than the deny weight");
        }

        foreach (var pair in Layers.All)
        {
            handle.BlockDns(providerKey,
                subLayerKey,
                pair.Value,
                weightDeny,
                "HecopNet_Filter",
                $"Block DNS ({pair.Key})");
        }

        foreach (var pair in Layers.V4)
        {
            handle.AddDnsV4(
                ActionType.Permit,
                providerKey,
                subLayerKey,
                pair.Value,
                weightAllow,
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork),
                "HecopNet_Filter",
                $"Allow DNS ({pair.Key})");
        }

        // foreach (var pair in Layers.V6)
        // {
        //     handle.AllowDnsV6(
        //         providerKey,
        //         subLayerKey,
        //         pair.Value,
        //         weightDeny,
        //         addresses.Where(address => address.AddressFamily == AddressFamily.InterNetworkV6),
        //         "HecopNet_Filter",
        //         $"Allow DNS ({pair.Key})");
        // }
    }

    public static void PermitNetworkInterface(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ulong ifLuid)
    {
        foreach (var pair in Layers.All)
        {
            handle.PermitNetworkInterface(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                ifLuid,
                "HecopNet_Filter",
                $"Permit traffic on TAP adapter ({pair.Key})");
        }
    }

    public static void AddPeerName(
        this SafeHandle handle,
        ActionType action,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        Uri uri)
    {
        foreach (var pair in new[] { Layers.V4.First() })
        {
            handle.AddPeerName(
                action,
                providerKey,
                subLayerKey,
                layerKey: pair.Value,
                uri,
                weight,
                "HecopNet_Filter",
                $"Permit traffic by peer name ({pair.Key})");
        }
    }

    public static void PermitSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPAddress address,
        IPAddress mask,
        bool isLocalAddress)
    {
        foreach (var pair in Layers.V4)
        {
            handle.AddSubNetworkV4(
                action: ActionType.Permit,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                address,
                mask,
                isLocalAddress,
                "HecopNet_Filter",
                $"Permit traffic on LAN network ({pair.Key})");
        }
    }

    public static void BlockSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPAddress address,
        IPAddress mask,
        bool isLocalAddress)
    {
        foreach (var pair in Layers.V4)
        {
            handle.AddSubNetworkV4(
                action: ActionType.Permit,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                address,
                mask,
                isLocalAddress,
                "HecopNet_Filter",
                $"Permit traffic on LAN network ({pair.Key})");
        }
    }

    public static void PermitLocalSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPNetwork2 network)
    {
        network = network ?? throw new ArgumentNullException(nameof(network));

        handle.PermitSubNetworkV4(providerKey, subLayerKey, weight, network.Network, network.Netmask, true);
    }

    public static void PermitRemoteSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPNetwork2 network)
    {
        network = network ?? throw new ArgumentNullException(nameof(network));

        handle.PermitSubNetworkV4(providerKey, subLayerKey, weight, network.Network, network.Netmask, false);
    }

    public static void BlockRemoteSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPNetwork2 network)
    {
        network = network ?? throw new ArgumentNullException(nameof(network));

        handle.BlockSubNetworkV4(providerKey, subLayerKey, weight, network.Network, network.Netmask, false);
    }

    public static void PermitTcpPortV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ushort port)
    {
        foreach (var pair in Layers.V4Port)
        {
            handle.PermitTcpPortV4(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                port,
                "HecopNet_Filter",
                $"Permit traffic on TCP port ({pair.Key})");
        }
    }

    public static void PermitUdpPortV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ushort port)
    {
        foreach (var pair in Layers.V4Port)
        {
            handle.PermitUdpPortV4(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                port,
                "HecopNet_Filter",
                $"Permit traffic on UDP port ({pair.Key})");
        }
    }

    public static void PermitProtocolV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        byte proto)
    {
        foreach (var pair in Layers.V4)
        {
            handle.PermitProtocolV4(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                proto,
                "HecopNet_Filter",
                $"Permit traffic for protocol ({pair.Key})");
        }
    }

    // ReSharper disable once InconsistentNaming
    // ReSharper disable once UnusedMember.Local
    //private static Guid cHVPN_WFP_CALLOUT_V4 { get; } = new Guid(
    //    0x2da40468, 0xb926, 0x4402,
    //    0xb3, 0xf8, 0xcb, 0x4e, 0x91, 0x27, 0x01, 0x59);

    //public void RegisterCallout(
    //    Guid providerKey)
    //{
    //    WfpMethods.AddCallout(
    //        WfpSession,
    //        cHVPN_WFP_CALLOUT_V4,
    //        providerKey,
    //        NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
    //        "HecopNet_Filter",
    //        "Split tunneling callout (IPv4)");
    //}

    //public Guid RegisterProviderContext(
    //    Guid providerKey,
    //    IPAddress ipAddress)
    //{
    //    return WfpMethods.AddProviderContext(
    //        WfpSession,
    //        providerKey,
    //        "HecopNet_Filter",
    //        "Register provider context for split tunneling callout driver",
    //        ipAddress);
    //}

    //public void EnableSplitApp(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    string appPath,
    //    byte weight,
    //    Guid providerContextKey)
    //{
    //    AllowSplitApps(providerKey, subLayerKey, new[] { appPath }, weight, providerContextKey, false);
    //}

    //public void AllowSplitApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    ICollection<string> paths,
    //    byte weight,
    //    Guid providerContextKey,
    //    bool reversed)
    //{
    //    var appIds = paths
    //        .Select(GetAppId)
    //        .ToArray();

    //    try
    //    {
    //        foreach (var appId in appIds)
    //        {
    //            PermitAppId(providerKey, subLayerKey, appId, weight);
    //        }

    //        AllowSplitAppIds(providerKey, appIds, weight, providerContextKey, reversed);
    //    }
    //    finally
    //    {
    //        foreach (var appId in appIds)
    //        {
    //            appId.Dispose();
    //        }
    //    }
    //}

    //public void AllowSplitAppIds(
    //    Guid providerKey,
    //    SafeFwpmHandle[] appIds,
    //    byte weight,
    //    Guid providerContextKey,
    //    bool reversed)
    //{
    //    WfpMethods.AllowSplitAppIds(
    //        WfpSession,
    //        providerKey,
    //        NativeConstants.cFWPM_SUBLAYER_UNIVERSAL,
    //        NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
    //        appIds,
    //        weight,
    //        providerContextKey,
    //        cHVPN_WFP_CALLOUT_V4,
    //        reversed,
    //        "HecopNet_Filter",
    //        "Enable split tunneling using callout (IPv4)");
    //}

    //public void EnableSplitAppId(
    //    Guid providerKey,
    //    SafeFwpmHandle appId,
    //    byte weight,
    //    Guid providerContextKey)
    //{
    //    AllowSplitAppIds(providerKey, new[] { appId }, weight, providerContextKey, false);
    //}

    public static void PermitLoopback(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        foreach (var pair in Layers.All)
        {
            handle.PermitLoopback(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                "HecopNet_Filter",
                $"Permit on loopback ({pair.Key})");
        }
    }

    public static void BlockAll(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        foreach (var pair in Layers.All)
        {
            handle.BlockAll(providerKey,
                subLayerKey,
                pair.Value,
                weight,
                "HecopNet_Filter",
                $"Block all ({pair.Key})");
        }
    }

    public static void PermitLan(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("192.168.0.0/16"));
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("172.16.0.0/12"));
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("10.0.0.0/8"));
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("224.0.0.0/4"));
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("169.254.0.0/16"));
        handle.PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("255.255.255.255/32"));
    }

    public static void PermitDns(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weightAllow,
        byte weightDeny,
        params string[] servers)
    {
        var dnsServers = new List<IPAddress>();
        foreach (var server in servers
            .Where(static server => !string.IsNullOrWhiteSpace(server)))
        {
            dnsServers.Add(IPAddress.Parse(server));
        }
        if (!dnsServers.Any())
        {
            dnsServers.Add(IPAddress.Parse("10.255.0.1"));
        }

        handle.PermitDns(providerKey, subLayerKey, weightAllow, weightDeny, dnsServers);
    }

    public static void PermitIKEv2(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        const byte cIPPROTO_IPinIP = 4;

        handle.PermitLocalSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork2.Parse("10.0.0.0/8"));
        handle.PermitProtocolV4(providerKey, subLayerKey, weight, cIPPROTO_IPinIP);
    }

    public static void PermitLocalhost(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        handle.PermitLoopback(providerKey, subLayerKey, weight);
    }

    //public void EnableSplitTunnelingForSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    bool reversed,
    //    params string[] applications)
    //{
    //    RegisterCallout(providerKey);

    //    var localProviderContextKey = RegisterProviderContext(
    //        providerKey,
    //        localIp);
    //    AllowSplitApps(
    //        providerKey,
    //        subLayerKey,
    //        applications,
    //        weight,
    //        localProviderContextKey,
    //        !reversed);

    //    var vpnProviderContextKey = RegisterProviderContext(
    //        providerKey,
    //        vpnIp);
    //    AllowSplitApps(
    //        providerKey,
    //        subLayerKey,
    //        applications,
    //        weight,
    //        vpnProviderContextKey,
    //        reversed);
    //}

    //public void EnableSplitTunnelingOnlyForSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    params string[] applications)
    //{
    //    EnableSplitTunnelingForSelectedApps(
    //        providerKey,
    //        subLayerKey,
    //        weight,
    //        localIp,
    //        vpnIp,
    //        false,
    //        applications);
    //}

    //public void EnableSplitTunnelingExcludeSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    params string[] applications)
    //{
    //    EnableSplitTunnelingForSelectedApps(
    //        providerKey,
    //        subLayerKey,
    //        weight,
    //        localIp,
    //        vpnIp,
    //        true,
    //        applications);
    //}
}
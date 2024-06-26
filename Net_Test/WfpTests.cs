﻿using Hecop_WFP;
using HecopNet_Filter;
using System.Net;

namespace Hecop_WFP.Tests;


public class WfpTests
{

    public void HFirewallTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();
        _ = firewall.WfpSession.RegisterKeys();
    }


    public async Task AllowOnlyChromeLanDnsAndLocalhostTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();
        firewall.RunTransaction(handle =>
        {
            var (providerKey, subLayerKey) = handle.RegisterKeys();
            handle.AddAppId(
                ActionType.Permit,
                providerKey,
                subLayerKey,
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                15);

            handle.PermitLan(providerKey, subLayerKey, 12);
            handle.PermitDns(providerKey, subLayerKey, 11, 10);
            handle.PermitLocalhost(providerKey, subLayerKey, 1);

            // Block everything not allowed explicitly
            handle.BlockAll(providerKey, subLayerKey, 0);
        });

        await Task.Delay(TimeSpan.FromSeconds(15));
    }


    public async Task AllowOnlyChromeLanDnsAndLocalhostTestBuilder()
    {
        using var firewall = new FirewallBuilder()
            .Block()
            .All()
            .Allow()
            .Localhost()
            .DomainNameSystem()
            .LocalAreaNetwork()
            .Url("https://www.bing.com/")
            .Application(@"C:\Program Files\Google\Chrome\Application\chrome.exe")
            .Build();

        await Task.Delay(TimeSpan.FromSeconds(15));
    }


    public async Task BlockBingOnly()
    {
        using var firewall = new FirewallBuilder()
            .Block()
            .Url("https://www.bing.com/")
            .Build();

        await Task.Delay(TimeSpan.FromSeconds(15));
    }


    public async Task BlockAppAndPermitSomeNetworks()
    {
        using var firewall = new FirewallBuilder()
            .Block()
            .Application(@"C:\Program Files\Google\Chrome\Application\chrome.exe")
        .Allow()
            .RemoteSubNetwork(IPNetwork2.Parse("216.0.0.0/8"))
            .Build();

        await Task.Delay(TimeSpan.FromSeconds(60));
    }


    public void GetAppIdFromFileNameTest()
    {
        using (SessionExtensions.GetAppId(@"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe"))
        {
        }
    }


    public void WfpSessionNotOpenDisposeTest()
    {
        using (new HFirewall())
        {
        }
    }


    public void WfpSessionNotOpenRunTransactionTest()
    {
        //Assert.ThrowsException<COMException>(() =>
        //{
        //    using var firewall = new HFirewall();
        //    firewall.RunTransaction(_ => { });
        //});
    }
}
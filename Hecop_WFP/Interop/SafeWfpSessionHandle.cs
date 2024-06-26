﻿using System;
using System.Runtime.Versioning;
using System.Security;

namespace Hecop_WFP.Interop;

[SecurityCritical]
[SupportedOSPlatform("windows6.0.6000")]
public sealed class SafeWfpSessionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWfpSessionHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeWfpSessionHandle(IntPtr preexistingHandle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(preexistingHandle);
    }

    [SecurityCritical]
    protected override bool ReleaseHandle()
    {
        var result = PInvoke.FwpmEngineClose0(new HANDLE(handle));

        return result == 0;
    }
}
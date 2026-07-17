using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace DarksFIDO2.Provider;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ProviderProcessHardening.Apply();
        try
        {
            string mode = args.FirstOrDefault()?.ToLowerInvariant() ?? "--com-server";
            return mode switch
            {
                "--register" => ProviderRegistration.Register(Environment.ProcessPath!),
                "--unregister" => ProviderRegistration.Unregister(),
                "--status" => ProviderRegistration.WriteStatus(),
                "--self-test" => ProviderSelfTest.Run(),
                "--com-server" or "-embedding" => ComServer.Run(),
                _ => 64
            };
        }
        catch (Exception ex)
        {
            ProviderLog.Write(Guid.Empty, "Process", "Stopped after " + ex.GetType().Name + ".");
            return Marshal.GetHRForException(ex);
        }
    }
}

internal static class ProviderProcessHardening
{
    internal static void Apply()
    {
        try { SetProcessDEPPolicy(1); } catch { }
        try { var policy = new MitigationPolicy { Flags = 1 }; SetMitigation(6, ref policy, Marshal.SizeOf<MitigationPolicy>()); } catch { }
        try { var policy = new MitigationPolicy { Flags = 7 }; SetMitigation(10, ref policy, Marshal.SizeOf<MitigationPolicy>()); } catch { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct MitigationPolicy { public uint Flags; }
    [DllImport("kernel32.dll")] private static extern bool SetProcessDEPPolicy(uint flags);
    [DllImport("kernel32.dll", EntryPoint = "SetProcessMitigationPolicy", SetLastError = true)] private static extern bool SetMitigation(int policy, ref MitigationPolicy buffer, int length);
}

internal static class ProviderRegistration
{
    public static int Register(string executable)
    {
        if (!NativeMethods.PluginRuntimeAvailable()) return unchecked((int)0x80004001);
        if (NativeMethods.GetAuthenticatorState(out _) >= 0) return 0;
        using RegistryKey key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\CLSID\{{{ProviderIds.ClassId:D}}}\LocalServer32", true);
        key.SetValue(null, $"\"{executable}\" --com-server");
        key.SetValue("ServerExecutable", executable);

        byte[] info = ProviderIds.AuthenticatorInfo();
        byte[] logo = ProviderIds.LogoSvgBase64();
        int hr = NativeMethods.AddAuthenticator(info, logo, out byte[] operationSigningKey);
        if (hr < 0)
        {
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\CLSID\{{{ProviderIds.ClassId:D}}}", false);
            return hr;
        }
        using RegistryKey state = Registry.CurrentUser.CreateSubKey(@"Software\DarksFIDO2\PasskeyProvider", true);
        state.SetValue("OperationSigningPublicKey", operationSigningKey, RegistryValueKind.Binary);
        state.SetValue("ProviderPath", executable);
        state.SetValue("RegisteredUtc", DateTimeOffset.UtcNow.ToString("O"));
        return 0;
    }

    public static int Unregister()
    {
        int hr = NativeMethods.RemoveAuthenticator();
        Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\CLSID\{{{ProviderIds.ClassId:D}}}", false);
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\DarksFIDO2\PasskeyProvider", false);
        return hr == unchecked((int)0x80090011) ? 0 : hr;
    }

    public static int WriteStatus()
    {
        int hr = NativeMethods.GetAuthenticatorState(out int state);
        string text = hr < 0 ? $"Unavailable|0x{hr:X8}" : state == 1 ? "Enabled" : "RegisteredDisabled";
        Console.WriteLine(text);
        return hr < 0 ? hr : 0;
    }
}

internal static class ProviderSelfTest
{
    public static int Run()
    {
        if (!NativeMethods.PluginRuntimeAvailable()) return 1;
        byte[] sample = DarksFIDO2.Core.Passkeys.CtapCbor.Encode(new Dictionary<object, object?>
        {
            [1L] = RandomNumberGenerator.GetBytes(32),
            [2L] = new Dictionary<object, object?> { ["id"] = "example.com", ["name"] = "Example" }
        });
        _ = DarksFIDO2.Core.Passkeys.CtapCbor.Decode(sample);
        return 0;
    }
}

internal static class ComServer
{
    public static int Run()
    {
        int hr = NativeMethods.CoInitializeEx(IntPtr.Zero, 2);
        if (hr < 0) return hr;
        IntPtr factoryUnknown = IntPtr.Zero;
        try
        {
            var factory = new PluginClassFactory();
            factoryUnknown = Marshal.GetIUnknownForObject(factory);
            Guid clsid = ProviderIds.ClassId;
            hr = NativeMethods.CoRegisterClassObject(ref clsid, factoryUnknown, 4, 1, out uint cookie);
            if (hr < 0) return hr;
            try
            {
                using var idle = new ManualResetEvent(false);
                idle.WaitOne(TimeSpan.FromMinutes(5));
            }
            finally { NativeMethods.CoRevokeClassObject(cookie); }
            GC.KeepAlive(factory);
            return 0;
        }
        finally
        {
            if (factoryUnknown != IntPtr.Zero) Marshal.Release(factoryUnknown);
            NativeMethods.CoUninitialize();
        }
    }
}

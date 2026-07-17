using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using DarksFIDO2.Core.Passkeys;

namespace DarksFIDO2.Core.Interop;

public sealed class PasskeyProviderService
{
    private static readonly Guid ProviderClassId = new("AA84D912-9B38-4E8F-B37E-7C95687A2D41");
    public string ExecutablePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "darksfido2-provider.exe");

    public PasskeyProviderStatus GetStatus()
    {
        if (!File.Exists(ExecutablePath)) return new(PasskeyProviderState.Missing, "The virtual passkey companion is not installed.");
        try
        {
            Guid classId = ProviderClassId;
            int hr = WebAuthNPluginGetAuthenticatorState(ref classId, out int state);
            if (hr == unchecked((int)0x80090011)) return new(PasskeyProviderState.NotRegistered, "Ready to register with Windows.");
            if (hr < 0) return new(PasskeyProviderState.RuntimeUnavailable, $"Windows passkey plugin API returned 0x{hr:X8}.");
            return state == 1
                ? new(PasskeyProviderState.Enabled, "Enabled. Windows will start it automatically for passkey requests.")
                : new(PasskeyProviderState.RegisteredDisabled, "Registered. Enable it once in Windows Passkey Advanced Options.");
        }
        catch (EntryPointNotFoundException) { return new(PasskeyProviderState.RuntimeUnavailable, "This Windows build does not include the passkey plugin API."); }
        catch (DllNotFoundException) { return new(PasskeyProviderState.RuntimeUnavailable, "Windows WebAuthn is unavailable."); }
    }

    public void Register()
    {
        if (!File.Exists(ExecutablePath)) throw new FileNotFoundException("The virtual passkey companion is missing.", ExecutablePath);
        int exit = Run("--register");
        if (exit != 0) throw new InvalidOperationException($"Windows rejected provider registration (0x{exit:X8}).");
    }

    public void OpenWindowsSettings() => Process.Start(new ProcessStartInfo("ms-settings:passkeys") { UseShellExecute = true });

    public static unsafe void RemoveCredentialMetadata(SoftwarePasskeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (credential.CredentialId is null || credential.CredentialId.Length is < 1 or > 1_024 ||
            credential.UserId is null || credential.UserId.Length is < 1 or > 64)
            throw new ArgumentException("The provider credential metadata is invalid.", nameof(credential));

        Guid classId = ProviderClassId;
        byte[] rpId = Encoding.Unicode.GetBytes(credential.RpId + "\0");
        byte[] rpName = Encoding.Unicode.GetBytes(credential.RpName + "\0");
        byte[] userName = Encoding.Unicode.GetBytes(credential.UserName + "\0");
        byte[] displayName = Encoding.Unicode.GetBytes(credential.UserDisplayName + "\0");
        fixed (byte* pCredentialId = credential.CredentialId)
        fixed (byte* pUserId = credential.UserId)
        fixed (byte* pRpId = rpId)
        fixed (byte* pRpName = rpName)
        fixed (byte* pUserName = userName)
        fixed (byte* pDisplayName = displayName)
        {
            var details = new PluginCredentialDetails
            {
                CredentialIdLength = (uint)credential.CredentialId.Length,
                CredentialId = (IntPtr)pCredentialId,
                RpId = (IntPtr)pRpId,
                RpName = (IntPtr)pRpName,
                UserIdLength = (uint)credential.UserId.Length,
                UserId = (IntPtr)pUserId,
                UserName = (IntPtr)pUserName,
                UserDisplayName = (IntPtr)pDisplayName
            };
            int hr = WebAuthNPluginAuthenticatorRemoveCredentials(ref classId, 1, ref details);
            if (hr < 0 && hr != unchecked((int)0x80090011))
                Marshal.ThrowExceptionForHR(hr);
        }
    }

    private int Run(string arguments)
    {
        using Process process = Process.Start(new ProcessStartInfo(ExecutablePath, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        }) ?? throw new InvalidOperationException("Unable to start the passkey companion.");
        if (!process.WaitForExit(30_000)) { process.Kill(true); throw new TimeoutException("The passkey companion did not respond."); }
        return process.ExitCode;
    }

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNPluginGetAuthenticatorState(ref Guid classId, out int state);

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNPluginAuthenticatorRemoveCredentials(ref Guid classId, uint count, ref PluginCredentialDetails details);

    [StructLayout(LayoutKind.Sequential)]
    private struct PluginCredentialDetails
    {
        internal uint CredentialIdLength;
        internal IntPtr CredentialId;
        internal IntPtr RpId;
        internal IntPtr RpName;
        internal uint UserIdLength;
        internal IntPtr UserId;
        internal IntPtr UserName;
        internal IntPtr UserDisplayName;
    }
}

public enum PasskeyProviderState { Missing, RuntimeUnavailable, NotRegistered, RegisteredDisabled, Enabled }
public sealed record PasskeyProviderStatus(PasskeyProviderState State, string Detail);

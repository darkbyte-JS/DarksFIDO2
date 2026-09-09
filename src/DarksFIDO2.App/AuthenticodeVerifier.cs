using System.Runtime.InteropServices;
using System.IO;

namespace DarksFIDO2.App;

internal static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    internal static bool IsTrusted(string path)
    {
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr filePointer = IntPtr.Zero;
        try
        {
            pathPointer = Marshal.StringToCoTaskMemUni(Path.GetFullPath(path));
            var file = new WinTrustFileInfo
            {
                Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer
            };
            filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(file, filePointer, false);
            var data = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2, // WTD_UI_NONE
                RevocationChecks = 0,
                UnionChoice = 1, // WTD_CHOICE_FILE
                FileInfo = filePointer,
                StateAction = 0,
                ProviderFlags = 0x10 | 0x1000 // no revocation network lookup; cache-only URL retrieval
            };
            Guid action = GenericVerifyV2;
            return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0;
        }
        catch { return false; }
        finally
        {
            if (filePointer != IntPtr.Zero) Marshal.FreeHGlobal(filePointer);
            if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid actionId, ref WinTrustData trustData);
}

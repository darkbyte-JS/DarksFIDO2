using System;
using System.Runtime.InteropServices;

namespace DarksFIDO2.App.Services;

public interface IWindowProtection
{
    void ApplyProtection(IntPtr hwnd);
}

public sealed class WindowProtection : IWindowProtection
{
    private const uint WDA_NONE = 0x00000000;
    private const uint WDA_MONITOR = 0x00000001;
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private const int SM_REMOTESESSION = 0x1000;

    public void ApplyProtection(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return;

        // If in Remote Desktop Session or capture protection is explicitly disabled,
        // do not apply WDA_EXCLUDEFROMCAPTURE because it blinds the user with a solid black screen.
        bool isRemote = GetSystemMetrics(SM_REMOTESESSION) != 0;
        bool disabled = Environment.GetEnvironmentVariable("DARKSFIDO2_DISABLE_CAPTURE_PROTECTION") == "1";

        if (isRemote || disabled)
        {
            SetWindowDisplayAffinity(hwnd, WDA_NONE);
            return;
        }

        // Apply WDA_EXCLUDEFROMCAPTURE (Windows 10 2004+ / Windows 11)
        // Completely excludes window from screenshots, screen recorders, Discord, OBS, and Teams
        bool success = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        if (!success)
        {
            // Fallback to WDA_MONITOR if high affinity not supported
            SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        }
    }
}

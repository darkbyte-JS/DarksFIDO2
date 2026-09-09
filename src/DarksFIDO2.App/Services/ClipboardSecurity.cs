using System;
using System.Runtime.InteropServices;
using System.Windows.Threading;

namespace DarksFIDO2.App.Services;

public interface IClipboardSecurity
{
    void CopySensitive(string text, int autoPurgeSeconds = 30);
    void ClearClipboard();
}

public sealed class ClipboardSecurity : IClipboardSecurity
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint RegisterClipboardFormat(string lpszFormat);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;
    private const uint GMEM_ZEROINIT = 0x0040;

    private static readonly uint FormatExcludeHistory = RegisterClipboardFormat("CanIncludeInClipboardHistory");
    private static readonly uint FormatExcludeCloud = RegisterClipboardFormat("CanUploadToCloudClipboard");
    private static readonly uint FormatExcludeMonitor = RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing");

    private DispatcherTimer? _purgeTimer;
    private string? _lastCopiedSensitive;

    public void CopySensitive(string text, int autoPurgeSeconds = 30)
    {
        if (string.IsNullOrEmpty(text)) return;

        _lastCopiedSensitive = text;

        for (int attempt = 0; attempt < 5; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    EmptyClipboard();

                    // 1. Prevent Windows 11 Clipboard History (Win+V)
                    SetDwordFormat(FormatExcludeHistory, 0);

                    // 2. Prevent Windows 11 Cloud Clipboard Sync
                    SetDwordFormat(FormatExcludeCloud, 0);

                    // 3. Prevent external clipboard monitors / password manager sniffing
                    SetDwordFormat(FormatExcludeMonitor, 1);

                    // 4. Set Unicode text
                    SetUnicodeText(text);
                    break;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            System.Threading.Thread.Sleep(20);
        }

        // Schedule auto-purge
        _purgeTimer?.Stop();
        if (autoPurgeSeconds > 0)
        {
            _purgeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(autoPurgeSeconds) };
            _purgeTimer.Tick += (s, e) =>
            {
                _purgeTimer?.Stop();
                PurgeIfMatch();
            };
            _purgeTimer.Start();
        }
    }

    private void PurgeIfMatch()
    {
        try
        {
            if (System.Windows.Clipboard.ContainsText())
            {
                string current = System.Windows.Clipboard.GetText();
                if (current == _lastCopiedSensitive)
                {
                    ClearClipboard();
                }
            }
        }
        catch { }
        finally
        {
            _lastCopiedSensitive = null;
        }
    }

    public void ClearClipboard()
    {
        for (int i = 0; i < 5; i++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    EmptyClipboard();
                    break;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            System.Threading.Thread.Sleep(20);
        }
    }

    private static void SetDwordFormat(uint format, uint value)
    {
        if (format == 0) return;
        IntPtr hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (UIntPtr)4);
        if (hMem == IntPtr.Zero) return;

        IntPtr pMem = GlobalLock(hMem);
        if (pMem != IntPtr.Zero)
        {
            Marshal.WriteInt32(pMem, (int)value);
            GlobalUnlock(hMem);
            SetClipboardData(format, hMem);
        }
        else
        {
            GlobalFree(hMem);
        }
    }

    private static void SetUnicodeText(string text)
    {
        int bytesCount = (text.Length + 1) * 2;
        IntPtr hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (UIntPtr)bytesCount);
        if (hMem == IntPtr.Zero) return;

        IntPtr pMem = GlobalLock(hMem);
        if (pMem != IntPtr.Zero)
        {
            char[] chars = text.ToCharArray();
            Marshal.Copy(chars, 0, pMem, chars.Length);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
        else
        {
            GlobalFree(hMem);
        }
    }
}

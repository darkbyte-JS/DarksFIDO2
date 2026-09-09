using System;
using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace DarksFIDO2.App.Services;

public interface IGlobalHotkey : IDisposable
{
    event Action? HotkeyPressed;
    void Register(IntPtr hwnd);
    void Unregister();
}

public sealed class GlobalHotkey : IGlobalHotkey
{
    private const int HOTKEY_ID = 0xD2F2;
    private const uint MOD_CONTROL = 0x0002;
    private const uint VK_L = 0x4C;
    private const int WM_HOTKEY = 0x0312;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    private IntPtr _hwnd = IntPtr.Zero;
    private HwndSource? _source;
    public event Action? HotkeyPressed;

    public void Register(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return;
        Unregister();

        _hwnd = hwnd;
        _source = HwndSource.FromHwnd(hwnd);
        _source?.AddHook(HwndHook);

        RegisterHotKey(_hwnd, HOTKEY_ID, MOD_CONTROL, VK_L);
    }

    public void Unregister()
    {
        if (_hwnd != IntPtr.Zero)
        {
            UnregisterHotKey(_hwnd, HOTKEY_ID);
            _source?.RemoveHook(HwndHook);
            _source = null;
            _hwnd = IntPtr.Zero;
        }
    }

    private IntPtr HwndHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == HOTKEY_ID)
        {
            handled = true;
            HotkeyPressed?.Invoke();
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        Unregister();
    }
}

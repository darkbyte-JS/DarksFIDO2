using System.Runtime.InteropServices;
using System.Windows;

namespace DarksFIDO2.App;

public partial class App : Application
{
    private Mutex? _singleInstance;
    private bool _ownsMutex;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstance = new Mutex(initiallyOwned: true, "Local\\DarksFIDO2.Desktop", out bool created);
        _ownsMutex = created;
        if (!created)
        {
            try
            {
                using var current = System.Diagnostics.Process.GetCurrentProcess();
                var existing = System.Diagnostics.Process.GetProcessesByName("DarksFIDO2").FirstOrDefault(p => p.Id != current.Id);
                if (existing != null)
                {
                    IntPtr targetHwnd = IntPtr.Zero;
                    ProcessHardening.EnumWindows((hwnd, _) =>
                    {
                        ProcessHardening.GetWindowThreadProcessId(hwnd, out uint pid);
                        if (pid == existing.Id && ProcessHardening.IsWindowVisible(hwnd))
                        {
                            var sb = new System.Text.StringBuilder(256);
                            ProcessHardening.GetWindowText(hwnd, sb, 256);
                            string title = sb.ToString();
                            if (title.Contains("DarksFIDO2") || title.Contains("Darks FIDO2"))
                            {
                                targetHwnd = hwnd;
                                return false;
                            }
                        }
                        return true;
                    }, IntPtr.Zero);

                    if (targetHwnd != IntPtr.Zero)
                    {
                        ProcessHardening.ShowWindow(targetHwnd, 9); // SW_RESTORE
                        ProcessHardening.SetForegroundWindow(targetHwnd);
                    }
                }
            }
            catch { }
            Shutdown();
            return;
        }

        ProcessHardening.ApplySafeMitigations();

        DispatcherUnhandledException += (_, args) =>
        {
            try
            {
                var dialogs = new Services.DialogService();
                dialogs.ShowError("Darks FIDO2 stopped an unexpected operation. Details were withheld to avoid exposing sensitive data.\n\nError type: " + args.Exception.GetType().Name, "Operation Stopped");
            }
            catch
            {
                // Fallback silently if UI dispatcher is faulted
            }

            if (MainWindow == null || !MainWindow.IsLoaded)
            {
                Shutdown(-1);
                return;
            }

            args.Handled = true;
        };

        try
        {
            var window = new MainWindow();
            MainWindow = window;
            window.Show();
            window.Activate();
            window.Focus();
        }
        catch (Exception ex)
        {
            try
            {
                var dialogs = new Services.DialogService();
                dialogs.ShowError("Failed to initialize application interface: " + ex.Message, "Startup Error");
            }
            catch { }
            Shutdown(-1);
            return;
        }
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex) _singleInstance?.ReleaseMutex();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }
}

internal static class ProcessHardening
{
    public static void ApplySafeMitigations()
    {
        try { SetProcessDEPPolicy(1); } catch { }
        try
        {
            var policy = new ExtensionPointPolicy { Flags = 1 };
            SetExtensionPointPolicy(6, ref policy, Marshal.SizeOf<ExtensionPointPolicy>());
        }
        catch { }
        try
        {
            // Flags = 3 (NoRemoteImages | NoLowMandatoryLabelImages)
            // Blocks remote and low-integrity DLL loading without breaking runtime WPF assembly resolution
            var policy = new ImageLoadPolicy { Flags = 3 };
            SetImageLoadPolicy(10, ref policy, Marshal.SizeOf<ImageLoadPolicy>());
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct ExtensionPointPolicy { public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ImageLoadPolicy { public uint Flags; }
    [DllImport("kernel32.dll")] private static extern bool SetProcessDEPPolicy(uint flags);
    [DllImport("kernel32.dll", EntryPoint = "SetProcessMitigationPolicy", SetLastError = true)] private static extern bool SetExtensionPointPolicy(int policy, ref ExtensionPointPolicy buffer, int length);
    [DllImport("kernel32.dll", EntryPoint = "SetProcessMitigationPolicy", SetLastError = true)] private static extern bool SetImageLoadPolicy(int policy, ref ImageLoadPolicy buffer, int length);

    internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] internal static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] internal static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] internal static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] internal static extern bool SetForegroundWindow(IntPtr hWnd);
}

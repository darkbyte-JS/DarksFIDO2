using System.Runtime.InteropServices;
using System.Windows;

namespace DarksFIDO2.App;

public partial class App : Application
{
    private Mutex? _singleInstance;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstance = new Mutex(initiallyOwned: true, "Local\\DarksFIDO2.Desktop", out bool created);
        _ownsMutex = created;
        if (!created)
        {
            MessageBox.Show("Darks FIDO2 is already running.", "Darks FIDO2", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }
        ProcessHardening.ApplySafeMitigations();
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show("Darks FIDO2 stopped an unexpected operation. Details were withheld to avoid exposing sensitive data.\n\nError type: " + args.Exception.GetType().Name,
                "Operation stopped", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
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
            var policy = new ImageLoadPolicy { Flags = 7 }; // no remote/low-integrity images; prefer System32
            SetImageLoadPolicy(10, ref policy, Marshal.SizeOf<ImageLoadPolicy>());
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct ExtensionPointPolicy { public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ImageLoadPolicy { public uint Flags; }
    [DllImport("kernel32.dll")] private static extern bool SetProcessDEPPolicy(uint flags);
    [DllImport("kernel32.dll", EntryPoint = "SetProcessMitigationPolicy", SetLastError = true)] private static extern bool SetExtensionPointPolicy(int policy, ref ExtensionPointPolicy buffer, int length);
    [DllImport("kernel32.dll", EntryPoint = "SetProcessMitigationPolicy", SetLastError = true)] private static extern bool SetImageLoadPolicy(int policy, ref ImageLoadPolicy buffer, int length);
}

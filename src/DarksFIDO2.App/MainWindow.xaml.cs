using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Interop;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;
using DarksFIDO2.App.ViewModels;

namespace DarksFIDO2.App;

public partial class MainWindow : Window
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;
    private readonly IClipboardSecurity _clipboard;
    private readonly IQrCaptureService _qrCapture;
    private readonly IWindowProtection _windowProtection;
    private readonly IGlobalHotkey _globalHotkey;
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();

        _session = new VaultSession();
        _dialogs = new DialogService();
        _clipboard = new ClipboardSecurity();
        _qrCapture = new QrCaptureService();
        _windowProtection = new WindowProtection();
        _globalHotkey = new GlobalHotkey();

        _viewModel = new MainViewModel(_session, _dialogs, _clipboard, _qrCapture);
        DataContext = _viewModel;

        SourceInitialized += OnSourceInitialized;
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var helper = new WindowInteropHelper(this);
        IntPtr hwnd = helper.Handle;

        if (hwnd != IntPtr.Zero)
        {
            // Security Invariant: Window Display Affinity (WDA_EXCLUDEFROMCAPTURE)
            // Excludes window from screenshots, capture software, and stream recording
            _windowProtection.ApplyProtection(hwnd);

            // Security Invariant: Global Ctrl+L Emergency Vault Lock Hotkey
            _globalHotkey.Register(hwnd);
            _globalHotkey.HotkeyPressed += () =>
            {
                Dispatcher.Invoke(() => _session.Lock());
            };
        }
    }

    private void BtnMinimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void BtnMaximize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        _globalHotkey.Dispose();
        _session.Dispose();
        base.OnClosing(e);
    }
}

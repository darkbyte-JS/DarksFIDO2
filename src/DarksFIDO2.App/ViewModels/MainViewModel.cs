using System;
using System.Windows.Input;
using DarksFIDO2.App.Controls;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;

namespace DarksFIDO2.App.ViewModels;

public enum ConsoleSection
{
    Credentials,
    Hardware,
    Audit,
    Settings
}

public sealed class MainViewModel : ViewModelBase
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;
    private readonly IClipboardSecurity _clipboard;
    private readonly IQrCaptureService _qrCapture;

    private ConsoleSection _activeSection = ConsoleSection.Credentials;
    private string _autoLockDisplay = "05:00";

    public MainViewModel(
        IVaultSession session,
        IDialogService dialogs,
        IClipboardSecurity clipboard,
        IQrCaptureService qrCapture)
    {
        _session = session;
        _dialogs = dialogs;
        _clipboard = clipboard;
        _qrCapture = qrCapture;

        GateVM = new GateViewModel(_session, _dialogs);
        CredentialsVM = new CredentialsViewModel(_session, _dialogs, _clipboard, _qrCapture);
        HardwareVM = new HardwareViewModel(_session, _dialogs);
        AuditVM = new AuditViewModel(_session, _dialogs);
        SettingsVM = new SettingsViewModel(_session, _dialogs);

        _session.SessionChanged += OnSessionChanged;
        _session.AutoLockTick += OnAutoLockTick;

        LockCommand = new RelayCommand(() => _session.Lock());
        NavCredentialsCommand = new RelayCommand(() => ActiveSection = ConsoleSection.Credentials);
        NavHardwareCommand = new RelayCommand(() => ActiveSection = ConsoleSection.Hardware);
        NavAuditCommand = new RelayCommand(() => ActiveSection = ConsoleSection.Audit);
        NavSettingsCommand = new RelayCommand(() => ActiveSection = ConsoleSection.Settings);
        OpenGitHubCommand = new RelayCommand(() =>
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/darkbyte-JS") { UseShellExecute = true });
            }
            catch { }
        });
    }

    public GateViewModel GateVM { get; }
    public CredentialsViewModel CredentialsVM { get; }
    public HardwareViewModel HardwareVM { get; }
    public AuditViewModel AuditVM { get; }
    public SettingsViewModel SettingsVM { get; }

    public ICommand OpenGitHubCommand { get; }

    public bool IsUnlocked => _session.IsUnlocked;
    public bool IsLocked => !IsUnlocked;
    public string ActiveProfileName => _session.CurrentProfile?.Metadata.Name ?? "No Profile";
    public string TpmSummary => _session.Tpm.Detect().Present ? "TPM 2.0" : "No TPM";
    public PillVariant TpmVariant => _session.Tpm.Detect().Present ? PillVariant.Success : PillVariant.Danger;

    public string AutoLockDisplay
    {
        get => _autoLockDisplay;
        private set => SetProperty(ref _autoLockDisplay, value);
    }

    public ConsoleSection ActiveSection
    {
        get => _activeSection;
        set
        {
            if (SetProperty(ref _activeSection, value))
            {
                OnPropertyChanged(nameof(IsCredentialsActive));
                OnPropertyChanged(nameof(IsHardwareActive));
                OnPropertyChanged(nameof(IsAuditActive));
                OnPropertyChanged(nameof(IsSettingsActive));

                // Refresh the active view's data
                switch (value)
                {
                    case ConsoleSection.Credentials:
                        CredentialsVM.LoadItems();
                        break;
                    case ConsoleSection.Hardware:
                        HardwareVM.RefreshDiagnostics();
                        break;
                    case ConsoleSection.Audit:
                        AuditVM.LoadEvents();
                        break;
                    case ConsoleSection.Settings:
                        SettingsVM.LoadSettings();
                        break;
                }
            }
        }
    }

    public bool IsCredentialsActive => ActiveSection == ConsoleSection.Credentials;
    public bool IsHardwareActive => ActiveSection == ConsoleSection.Hardware;
    public bool IsAuditActive => ActiveSection == ConsoleSection.Audit;
    public bool IsSettingsActive => ActiveSection == ConsoleSection.Settings;

    public ICommand LockCommand { get; }
    public ICommand NavCredentialsCommand { get; }
    public ICommand NavHardwareCommand { get; }
    public ICommand NavAuditCommand { get; }
    public ICommand NavSettingsCommand { get; }

    private void OnSessionChanged()
    {
        OnPropertyChanged(nameof(IsUnlocked));
        OnPropertyChanged(nameof(IsLocked));
        OnPropertyChanged(nameof(ActiveProfileName));

        if (IsUnlocked)
        {
            CredentialsVM.LoadItems();
            HardwareVM.RefreshDiagnostics();
            AuditVM.LoadEvents();
            SettingsVM.LoadSettings();
            ActiveSection = ConsoleSection.Credentials;
        }
        else
        {
            GateVM.RefreshProfiles();
        }
    }

    private void OnAutoLockTick()
    {
        int remaining = _session.AutoLockRemainingSeconds;
        int mins = remaining / 60;
        int secs = remaining % 60;
        AutoLockDisplay = $"{mins:D2}:{secs:D2}";
    }
}

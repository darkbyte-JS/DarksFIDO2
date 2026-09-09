using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;
using DarksFIDO2.Core;
using DarksFIDO2.Core.Security;
using DarksFIDO2.Core.Storage;

namespace DarksFIDO2.App.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;

    private int _autoLockMinutes = 5;
    private bool _isDarkTheme = true;
    private bool _windowsHelloEnabled = true;

    public SettingsViewModel(IVaultSession session, IDialogService dialogs)
    {
        _session = session;
        _dialogs = dialogs;

        LoadSettings();

        SaveSettingsCommand = new RelayCommand(ExecuteSaveSettings);
        RotateKeyfileCommand = new RelayCommand(ExecuteRotateKeyfile);
        CreateBackupCommand = new RelayCommand(ExecuteCreateBackup);
        RestoreBackupCommand = new RelayCommand(ExecuteRestoreBackup);
        DeleteProfileCommand = new RelayCommand(ExecuteDeleteProfile);
    }

    public int AutoLockMinutes
    {
        get => _autoLockMinutes;
        set
        {
            if (SetProperty(ref _autoLockMinutes, value))
            {
                ExecuteSaveSettings();
            }
        }
    }

    public bool IsDarkTheme
    {
        get => _isDarkTheme;
        set
        {
            if (SetProperty(ref _isDarkTheme, value))
            {
                ApplyTheme(value ? AppTheme.Dark : AppTheme.Light);
                ExecuteSaveSettings();
            }
        }
    }

    public bool WindowsHelloEnabled
    {
        get => _windowsHelloEnabled;
        set
        {
            if (SetProperty(ref _windowsHelloEnabled, value))
            {
                ExecuteSaveSettings();
            }
        }
    }

    public string CurrentProfileName => _session.CurrentProfile?.Metadata.Name ?? "No Active Profile";
    public string CurrentProfileId => _session.CurrentProfile?.Metadata.Id.ToString() ?? "";
    public bool KeyfileRequired => _session.CurrentProfile?.Metadata.KeyfileRequired ?? false;

    public ICommand SaveSettingsCommand { get; }
    public ICommand RotateKeyfileCommand { get; }
    public ICommand CreateBackupCommand { get; }
    public ICommand RestoreBackupCommand { get; }
    public ICommand DeleteProfileCommand { get; }

    public void LoadSettings()
    {
        if (_session.CurrentProfile is null) return;
        AppSettings settings = _session.CurrentProfile.Data.Settings;
        _autoLockMinutes = settings.AutoLockMinutes;
        _windowsHelloEnabled = settings.WindowsHelloEnabled;
        _isDarkTheme = settings.Theme != AppTheme.Light;

        OnPropertyChanged(nameof(AutoLockMinutes));
        OnPropertyChanged(nameof(WindowsHelloEnabled));
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(CurrentProfileName));
        OnPropertyChanged(nameof(CurrentProfileId));
        OnPropertyChanged(nameof(KeyfileRequired));
    }

    private void ExecuteSaveSettings()
    {
        if (_session.CurrentProfile is null) return;
        _session.CurrentProfile.Data.Settings.AutoLockMinutes = AutoLockMinutes;
        _session.CurrentProfile.Data.Settings.WindowsHelloEnabled = WindowsHelloEnabled;
        _session.CurrentProfile.Data.Settings.Theme = IsDarkTheme ? AppTheme.Dark : AppTheme.Light;
        _session.Save();
    }

    private void ApplyTheme(AppTheme theme)
    {
        var app = Application.Current;
        var themeDict = new ResourceDictionary
        {
            Source = new Uri(theme == AppTheme.Light ? "Themes/LightTheme.xaml" : "Themes/DarkTheme.xaml", UriKind.Relative)
        };

        // Replace theme dictionary
        for (int i = 0; i < app.Resources.MergedDictionaries.Count; i++)
        {
            var dict = app.Resources.MergedDictionaries[i];
            if (dict.Source?.OriginalString.Contains("Theme.xaml") == true)
            {
                app.Resources.MergedDictionaries[i] = themeDict;
                return;
            }
        }
        app.Resources.MergedDictionaries.Add(themeDict);
    }

    private void ExecuteRotateKeyfile()
    {
        if (_session.CurrentProfile is null) return;

        string? currentPin = _dialogs.ShowPromptSecret("Enter your current Master PIN to authorize keyfile rotation:", "Authorize Keyfile Rotation");
        if (string.IsNullOrEmpty(currentPin)) return;

        var sfd = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save Replacement Master Keyfile",
            Filter = "Keyfile (*.dfkey)|*.dfkey|All Files (*.*)|*.*",
            FileName = $"{_session.CurrentProfile.Metadata.Name}-New.dfkey"
        };
        if (sfd.ShowDialog() != true) return;

        byte[] newKeyfile = RandomNumberGenerator.GetBytes(64);
        try
        {
            KeyfileRotationService.WriteThenCommit(sfd.FileName, newKeyfile, () =>
            {
                _session.Repository.ConfigureKeyfile(_session.CurrentProfile, currentPin, null, newKeyfile, null);
            });

            _session.AddAuditEvent("Security", "Success", $"Rotated companion keyfile for profile '{_session.CurrentProfile.Metadata.Name}'.");
            _dialogs.ShowAlert(
                $"Keyfile rotated successfully!\n\nNew Keyfile: {sfd.FileName}\n\nPlease ensure you keep this file safely backed up.",
                "Keyfile Rotated");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Keyfile rotation failed:\n{ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(newKeyfile);
        }
    }

    private void ExecuteCreateBackup()
    {
        if (_session.CurrentProfile is null) return;

        string? backupPassword = _dialogs.ShowPromptSecret("Enter a strong passphrase to encrypt this backup container (min 10 chars):", "Create Encrypted Backup");
        if (string.IsNullOrEmpty(backupPassword) || backupPassword.Length < 10)
        {
            _dialogs.ShowAlert("Backup passphrase must be at least 10 characters long.", "Validation Error");
            return;
        }

        var sfd = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save Encrypted Backup Container",
            Filter = "DarksFIDO2 Backup (*.dfb1)|*.dfb1|All Files (*.*)|*.*",
            FileName = $"{_session.CurrentProfile.Metadata.Name}-Backup-{DateTime.UtcNow:yyyyMMdd}.dfb1"
        };
        if (sfd.ShowDialog() != true) return;

        try
        {
            _session.Backup.Export(_session.CurrentProfile.Data, backupPassword, sfd.FileName);
            _session.AddAuditEvent("Backup", "Success", $"Created encrypted backup: {sfd.FileName}");
            _dialogs.ShowAlert(
                $"Encrypted backup container successfully created!\n\nLocation: {sfd.FileName}\nAlgorithm: AES-256-GCM + Argon2id KDF\n\nStore this backup file in a secure offline location.",
                "Backup Successful");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Failed to create backup: {ex.Message}");
        }
    }

    private void ExecuteRestoreBackup()
    {
        var ofd = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Encrypted Backup Container to Restore",
            Filter = "DarksFIDO2 Backup (*.dfb1)|*.dfb1|All Files (*.*)|*.*"
        };
        if (ofd.ShowDialog() != true) return;

        string? password = _dialogs.ShowPromptSecret("Enter the passphrase used to encrypt this backup container:", "Decrypt Backup");
        if (string.IsNullOrEmpty(password)) return;

        try
        {
            VaultData data = _session.Backup.Import(ofd.FileName, password);

            bool confirm = _dialogs.ShowConfirm(
                $"Backup verified successfully!\n\nProfile: {data.ProfileName}\nPasskeys: {data.FidoKeys.Count}\nTOTP Accounts: {data.TotpEntries.Count}\n\nRestore this vault now?",
                "Restore Backup");

            if (!confirm) return;

            if (_session.CurrentProfile is not null)
            {
                _session.CurrentProfile.Data.FidoKeys = data.FidoKeys;
                _session.CurrentProfile.Data.TotpEntries = data.TotpEntries;
                _session.CurrentProfile.Data.TpmKeys = data.TpmKeys;
                _session.CurrentProfile.Data.Settings = data.Settings;
                _session.Save();
                _session.AddAuditEvent("Backup", "Success", $"Restored vault from backup: {ofd.FileName}");
                _dialogs.ShowAlert("Vault restored successfully! The session will now reload.", "Restore Complete");
                _session.Lock();
            }
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Failed to restore backup:\n{ex.Message}");
        }
    }

    private void ExecuteDeleteProfile()
    {
        if (_session.CurrentProfile is null) return;

        string profileName = _session.CurrentProfile.Metadata.Name;
        string? confirmation = _dialogs.ShowPrompt(
            $"WARNING: Deleting profile '{profileName}' is permanent and cannot be undone.\n\nType the exact profile name to confirm deletion:",
            "Delete Profile Permanently");

        if (confirmation != profileName)
        {
            _dialogs.ShowAlert("Profile deletion cancelled. The entered name did not match.", "Deletion Cancelled");
            return;
        }

        try
        {
            var deletionService = new ProfileDeletionService();
            _session.Repository.Delete(_session.CurrentProfile, profileName, p => deletionService.DeleteOwnedKeys(p));
            _session.Lock();
            _session.ReloadProfiles();
            _dialogs.ShowAlert($"Profile '{profileName}' and all associated keys have been securely purged.", "Profile Deleted");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Failed to delete profile: {ex.Message}");
        }
    }
}

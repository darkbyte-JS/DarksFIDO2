using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Input;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;
using DarksFIDO2.Core;

namespace DarksFIDO2.App.ViewModels;

public sealed class GateViewModel : ViewModelBase
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;

    private ProfileSummary? _selectedProfile;
    private string _keyfilePath = string.Empty;
    private bool _hasKeyfile = false;
    private string _errorMessage = string.Empty;
    private bool _isBusy = false;

    public GateViewModel(IVaultSession session, IDialogService dialogs)
    {
        _session = session;
        _dialogs = dialogs;

        Profiles = new ObservableCollection<ProfileSummary>(_session.ProfileIndex.Profiles);
        _selectedProfile = Profiles.FirstOrDefault(p => p.Id == _session.ProfileIndex.LastProfileId) ?? Profiles.FirstOrDefault();

        RefreshKeyfileStatus();

        _session.SessionChanged += RefreshProfiles;

        UnlockCommand = new RelayCommand(ExecuteUnlock, () => !IsBusy && SelectedProfile is not null);
        CreateProfileCommand = new RelayCommand(ExecuteCreateProfile, () => !IsBusy);
        SelectKeyfileCommand = new RelayCommand(ExecuteSelectKeyfile, () => !IsBusy);
        RecoveryCommand = new RelayCommand(ExecuteRecovery, () => !IsBusy && SelectedProfile is not null);
    }

    public ObservableCollection<ProfileSummary> Profiles { get; }
    public bool HasProfiles => Profiles.Count > 0;
    public bool HasNoProfiles => Profiles.Count == 0;

    public void RefreshProfiles()
    {
        Profiles.Clear();
        foreach (var p in _session.ProfileIndex.Profiles)
        {
            Profiles.Add(p);
        }
        _selectedProfile = Profiles.FirstOrDefault(p => p.Id == _session.ProfileIndex.LastProfileId) ?? Profiles.FirstOrDefault();
        OnPropertyChanged(nameof(SelectedProfile));
        OnPropertyChanged(nameof(HasProfiles));
        OnPropertyChanged(nameof(HasNoProfiles));
        RefreshKeyfileStatus();
        (UnlockCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RecoveryCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    public ProfileSummary? SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            if (SetProperty(ref _selectedProfile, value))
            {
                ErrorMessage = string.Empty;
                RefreshKeyfileStatus();
                (UnlockCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (RecoveryCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public string KeyfilePath
    {
        get => _keyfilePath;
        set => SetProperty(ref _keyfilePath, value);
    }

    public bool HasKeyfile
    {
        get => _hasKeyfile;
        set => SetProperty(ref _hasKeyfile, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set => SetProperty(ref _errorMessage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                (UnlockCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public ICommand UnlockCommand { get; }
    public ICommand CreateProfileCommand { get; }
    public ICommand SelectKeyfileCommand { get; }
    public ICommand RecoveryCommand { get; }

    public void AttemptUnlock(string pin)
    {
        if (SelectedProfile is null)
        {
            ErrorMessage = "Please select a profile to unlock.";
            return;
        }

        if (string.IsNullOrEmpty(pin))
        {
            ErrorMessage = "Please enter the master PIN / passphrase.";
            return;
        }

        IsBusy = true;
        ErrorMessage = string.Empty;

        byte[]? keyfileBytes = null;
        try
        {
            if (SelectedProfile.KeyfileRequired)
            {
                if (string.IsNullOrWhiteSpace(KeyfilePath) || !File.Exists(KeyfilePath))
                {
                    ErrorMessage = "A companion keyfile (.dfkey) is required to unlock this profile.";
                    IsBusy = false;
                    return;
                }
                keyfileBytes = File.ReadAllBytes(KeyfilePath);
            }

            _session.Unlock(SelectedProfile.Id, pin, keyfileBytes);
        }
        catch (CryptographicException)
        {
            ErrorMessage = "Invalid master PIN, keyfile, or corrupted vault container.";
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            if (keyfileBytes is not null)
            {
                CryptographicOperations.ZeroMemory(keyfileBytes);
            }
            IsBusy = false;
        }
    }

    private void ExecuteUnlock()
    {
        // Handled via View event passing pin from PinBox
    }

    private void ExecuteCreateProfile()
    {
        var request = _dialogs.ShowCreateProfileDialog();
        if (request is null) return;

        try
        {
            _session.CreateProfile(request);
            RefreshProfiles();
            // If created with keyfile, offer to save it
            if (request.KeyfileBytes is { } keyBytes)
            {
                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Save Master Keyfile",
                    Filter = "Keyfile (*.dfkey)|*.dfkey|All Files (*.*)|*.*",
                    FileName = $"{request.Name}.dfkey"
                };
                if (sfd.ShowDialog() == true)
                {
                    File.WriteAllBytes(sfd.FileName, keyBytes);
                    _dialogs.ShowAlert($"Keyfile saved to:\n{sfd.FileName}\n\nKeep this file safe and backed up!", "Keyfile Created");
                }
            }
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Failed to create profile: {ex.Message}");
        }
    }

    private void ExecuteSelectKeyfile()
    {
        var ofd = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Companion Keyfile",
            Filter = "Keyfile (*.dfkey;*.keyfile;*.key)|*.dfkey;*.keyfile;*.key|All Files (*.*)|*.*"
        };
        if (ofd.ShowDialog() == true)
        {
            KeyfilePath = ofd.FileName;
            HasKeyfile = true;
        }
    }

    private void ExecuteRecovery()
    {
        if (SelectedProfile is null) return;

        string? phrase = _dialogs.ShowPrompt("Enter the 12 or 24-word emergency recovery phrase:", "Emergency Vault Recovery");
        if (string.IsNullOrWhiteSpace(phrase)) return;

        string? newPin = _dialogs.ShowPromptSecret("Enter a new master PIN for this vault:", "Set New Master PIN");
        if (string.IsNullOrWhiteSpace(newPin)) return;

        try
        {
            _session.UnlockWithRecovery(SelectedProfile.Id, newPin, phrase.Trim());
            _dialogs.ShowAlert("Vault unlocked via emergency recovery! Update your backup promptly.", "Recovery Successful");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Recovery failed: {ex.Message}", "Recovery Error");
        }
    }

    private void RefreshKeyfileStatus()
    {
        if (SelectedProfile is null)
        {
            HasKeyfile = false;
            KeyfilePath = string.Empty;
            return;
        }

        // Check if companion keyfile exists in profile dir or current working dir
        string companionInProfile = Path.Combine(_session.Paths.ProfileDirectory(SelectedProfile.Id), $"{SelectedProfile.Name}.dfkey");
        if (File.Exists(companionInProfile))
        {
            KeyfilePath = companionInProfile;
            HasKeyfile = true;
            return;
        }

        string companionInWorkingDir = Path.Combine(AppContext.BaseDirectory, $"{SelectedProfile.Name}.dfkey");
        if (File.Exists(companionInWorkingDir))
        {
            KeyfilePath = companionInWorkingDir;
            HasKeyfile = true;
            return;
        }

        HasKeyfile = !string.IsNullOrWhiteSpace(KeyfilePath) && File.Exists(KeyfilePath);
    }
}

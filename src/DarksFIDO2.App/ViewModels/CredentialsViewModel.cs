using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using DarksFIDO2.App.Controls;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;
using DarksFIDO2.Core;

namespace DarksFIDO2.App.ViewModels;

public enum CredentialFilterType
{
    All,
    Passkeys,
    Totp,
    HardwareBacked
}

public sealed class CredentialItemViewModel : ViewModelBase
{
    private string _totpCode = "------";
    private int _secondsRemaining = 30;
    private double _progress = 1.0;
    private bool _isCopied = false;

    public CredentialItemViewModel(FidoKeyRecord passkey)
    {
        IsPasskey = true;
        PasskeyData = passkey;
        Id = passkey.Id;
        Name = passkey.RpId;
        SecondaryInfo = passkey.UserName;
        TypeDisplay = passkey.Type.Contains("platform", StringComparison.OrdinalIgnoreCase) ? "Platform Passkey" : "Security Key";
        IsHardware = passkey.Type.Contains("platform", StringComparison.OrdinalIgnoreCase) || passkey.Transport.Contains("USB", StringComparison.OrdinalIgnoreCase);
        PillVariant = IsHardware ? PillVariant.Success : PillVariant.Info;
        PillText = IsHardware ? "TPM-HW" : "SOFTWARE";
    }

    public CredentialItemViewModel(TotpEntry totp)
    {
        IsPasskey = false;
        TotpData = totp;
        Id = totp.Id;
        Name = string.IsNullOrWhiteSpace(totp.Issuer) ? totp.Account : totp.Issuer;
        SecondaryInfo = totp.Account;
        TypeDisplay = $"TOTP ({totp.Digits}-digit {totp.Algorithm})";
        IsHardware = false;
        PillVariant = PillVariant.Neutral;
        PillText = $"{totp.Period}s";
        UpdateTotp();
    }

    public Guid Id { get; }
    public bool IsPasskey { get; }
    public FidoKeyRecord? PasskeyData { get; }
    public TotpEntry? TotpData { get; }

    public string Name { get; }
    public string SecondaryInfo { get; }
    public string TypeDisplay { get; }
    public bool IsHardware { get; }
    public PillVariant PillVariant { get; }
    public string PillText { get; }

    public string TotpCode
    {
        get => _totpCode;
        set => SetProperty(ref _totpCode, value);
    }

    public int SecondsRemaining
    {
        get => _secondsRemaining;
        set => SetProperty(ref _secondsRemaining, value);
    }

    public double Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    public bool IsCopied
    {
        get => _isCopied;
        set => SetProperty(ref _isCopied, value);
    }

    public void UpdateTotp()
    {
        if (TotpData is null) return;
        try
        {
            TotpCode code = TotpService.GetCode(TotpData);
            TotpCode = code.Code;
            SecondsRemaining = code.SecondsRemaining;
            Progress = code.Progress;
        }
        catch
        {
            TotpCode = "ERROR";
        }
    }

    public void MarkCopied()
    {
        IsCopied = true;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1500) };
        timer.Tick += (s, e) =>
        {
            timer.Stop();
            IsCopied = false;
        };
        timer.Start();
    }
}

public sealed class CredentialsViewModel : ViewModelBase
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;
    private readonly IClipboardSecurity _clipboard;
    private readonly IQrCaptureService _qrCapture;
    private readonly DispatcherTimer _totpTimer;

    private readonly ObservableCollection<CredentialItemViewModel> _allItems = [];
    private readonly ICollectionView _itemsView;

    private CredentialFilterType _activeFilter = CredentialFilterType.All;
    private string _searchQuery = string.Empty;
    private CredentialItemViewModel? _selectedItem;
    private bool _areSecretsRevealed = false;

    public CredentialsViewModel(IVaultSession session, IDialogService dialogs, IClipboardSecurity clipboard, IQrCaptureService qrCapture)
    {
        _session = session;
        _dialogs = dialogs;
        _clipboard = clipboard;
        _qrCapture = qrCapture;

        _itemsView = CollectionViewSource.GetDefaultView(_allItems);
        _itemsView.Filter = FilterItem;

        LoadItems();

        _totpTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _totpTimer.Tick += OnTotpTick;
        _totpTimer.Start();

        _session.SessionChanged += () =>
        {
            AreSecretsRevealed = false;
            LoadItems();
        };

        // Commands
        FilterAllCommand = new RelayCommand(() => SetFilter(CredentialFilterType.All));
        FilterPasskeysCommand = new RelayCommand(() => SetFilter(CredentialFilterType.Passkeys));
        FilterTotpCommand = new RelayCommand(() => SetFilter(CredentialFilterType.Totp));
        FilterHardwareCommand = new RelayCommand(() => SetFilter(CredentialFilterType.HardwareBacked));

        CopyTotpCommand = new RelayCommand(ExecuteCopyTotp);
        TestAssertionCommand = new RelayCommand(ExecuteTestAssertion);
        DeleteItemCommand = new RelayCommand(ExecuteDeleteItem);
        NewPasskeyCommand = new RelayCommand(ExecuteNewPasskey);
        NewTotpManualCommand = new RelayCommand(ExecuteNewTotpManual);
        SnipeScreenQrCommand = new RelayCommand(ExecuteSnipeScreenQr);
        ImportQrFileCommand = new RelayCommand(ExecuteImportQrFile);
        ToggleSecretsCommand = new RelayCommand(ExecuteToggleSecrets);
        OpenPasswordGeneratorCommand = new RelayCommand(() => _dialogs.ShowPasswordGenerator());
    }

    public ICollectionView Items => _itemsView;

    public CredentialItemViewModel? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (SetProperty(ref _selectedItem, value))
            {
                AreSecretsRevealed = false;
                OnPropertyChanged(nameof(DisplayCredentialId));
                OnPropertyChanged(nameof(DisplayPublicKey));
                OnPropertyChanged(nameof(SecretsToggleText));
            }
        }
    }

    public bool AreSecretsRevealed
    {
        get => _areSecretsRevealed;
        private set
        {
            if (SetProperty(ref _areSecretsRevealed, value))
            {
                OnPropertyChanged(nameof(DisplayCredentialId));
                OnPropertyChanged(nameof(DisplayPublicKey));
                OnPropertyChanged(nameof(SecretsToggleText));
            }
        }
    }

    public string SecretsToggleText => AreSecretsRevealed ? "Hide Secrets" : "Reveal Secrets (PIN)";

    public string DisplayCredentialId
    {
        get
        {
            if (SelectedItem?.PasskeyData is null) return string.Empty;
            return AreSecretsRevealed
                ? SelectedItem.PasskeyData.CredentialId
                : new string('●', 32);
        }
    }

    public string DisplayPublicKey
    {
        get
        {
            if (SelectedItem?.PasskeyData is null) return string.Empty;
            return AreSecretsRevealed
                ? SelectedItem.PasskeyData.PublicKeyCoseBase64
                : new string('●', 48);
        }
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                _itemsView.Refresh();
            }
        }
    }

    public CredentialFilterType ActiveFilter
    {
        get => _activeFilter;
        private set => SetProperty(ref _activeFilter, value);
    }

    public int TotalCount => _allItems.Count;
    public int PasskeyCount => _allItems.Count(x => x.IsPasskey);
    public int TotpCount => _allItems.Count(x => !x.IsPasskey);

    public ICommand FilterAllCommand { get; }
    public ICommand FilterPasskeysCommand { get; }
    public ICommand FilterTotpCommand { get; }
    public ICommand FilterHardwareCommand { get; }

    public ICommand CopyTotpCommand { get; }
    public ICommand TestAssertionCommand { get; }
    public ICommand DeleteItemCommand { get; }
    public ICommand NewPasskeyCommand { get; }
    public ICommand NewTotpManualCommand { get; }
    public ICommand SnipeScreenQrCommand { get; }
    public ICommand ImportQrFileCommand { get; }
    public ICommand ToggleSecretsCommand { get; }
    public ICommand OpenPasswordGeneratorCommand { get; }

    private void ExecuteToggleSecrets()
    {
        if (AreSecretsRevealed)
        {
            AreSecretsRevealed = false;
            return;
        }

        string? pin = _dialogs.ShowPromptSecret("Enter your master PIN to reveal cryptographic secrets:", "Master PIN Required");
        if (string.IsNullOrEmpty(pin))
        {
            return;
        }

        if (_session.VerifyCurrentPin(pin))
        {
            AreSecretsRevealed = true;
        }
        else
        {
            _dialogs.ShowError("Incorrect master PIN. Secrets remain sealed.", "Authentication Failed");
        }
    }

    public void LoadItems()
    {
        _allItems.Clear();
        if (_session.CurrentProfile is null) return;

        // Load passkeys
        foreach (FidoKeyRecord key in _session.CurrentProfile.Data.FidoKeys)
        {
            _allItems.Add(new CredentialItemViewModel(key));
        }

        // Load TOTP accounts
        foreach (TotpEntry totp in _session.CurrentProfile.Data.TotpEntries)
        {
            _allItems.Add(new CredentialItemViewModel(totp));
        }

        SelectedItem = _allItems.FirstOrDefault();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(PasskeyCount));
        OnPropertyChanged(nameof(TotpCount));
    }

    private void SetFilter(CredentialFilterType filter)
    {
        ActiveFilter = filter;
        _itemsView.Refresh();
    }

    private bool FilterItem(object obj)
    {
        if (obj is not CredentialItemViewModel item) return false;

        // Type filter
        switch (ActiveFilter)
        {
            case CredentialFilterType.Passkeys:
                if (!item.IsPasskey) return false;
                break;
            case CredentialFilterType.Totp:
                if (item.IsPasskey) return false;
                break;
            case CredentialFilterType.HardwareBacked:
                if (!item.IsHardware) return false;
                break;
        }

        // Search query
        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            string query = SearchQuery.Trim();
            bool nameMatch = item.Name.Contains(query, StringComparison.OrdinalIgnoreCase);
            bool secMatch = item.SecondaryInfo.Contains(query, StringComparison.OrdinalIgnoreCase);
            bool typeMatch = item.TypeDisplay.Contains(query, StringComparison.OrdinalIgnoreCase);
            if (!nameMatch && !secMatch && !typeMatch) return false;
        }

        return true;
    }

    private void OnTotpTick(object? sender, EventArgs e)
    {
        foreach (CredentialItemViewModel item in _allItems)
        {
            if (!item.IsPasskey)
            {
                item.UpdateTotp();
            }
        }
    }

    private void ExecuteCopyTotp(object? param)
    {
        CredentialItemViewModel? item = (param as CredentialItemViewModel) ?? SelectedItem;
        if (item is null || item.IsPasskey) return;

        item.UpdateTotp();
        _clipboard.CopySensitive(item.TotpCode, autoPurgeSeconds: 30);
        item.MarkCopied();
        _session.AddAuditEvent("Totp", "Success", $"Copied OTP code for '{item.Name}'. Auto-purge in 30s.");
    }

    private void ExecuteTestAssertion(object? param)
    {
        CredentialItemViewModel? item = (param as CredentialItemViewModel) ?? SelectedItem;
        if (item is null || !item.IsPasskey || item.PasskeyData is null) return;

        var helper = new System.Windows.Interop.WindowInteropHelper(Application.Current.MainWindow);
        try
        {
            uint newCounter = _session.WebAuthn.VerifyCredential(helper.Handle, item.PasskeyData);
            item.PasskeyData.SignCounter = newCounter;
            item.PasskeyData.LastUsedUtc = DateTimeOffset.UtcNow;
            item.PasskeyData.LastVerifiedUtc = DateTimeOffset.UtcNow;
            _session.Save();
            _session.AddAuditEvent("WebAuthn", "Success", $"Cryptographic assertion verified for '{item.PasskeyData.RpId}'. New counter: {newCounter}");
            _dialogs.ShowAlert($"Cryptographic assertion successfully verified!\n\nRelying Party: {item.PasskeyData.RpId}\nSign Counter: {newCounter}\nBiometric / User Presence: Confirmed", "Assertion Verified");
        }
        catch (Exception ex)
        {
            _session.AddAuditEvent("WebAuthn", "Failure", $"Assertion verification failed for '{item.PasskeyData.RpId}': {ex.Message}");
            _dialogs.ShowError($"WebAuthn assertion failed:\n{ex.Message}", "Verification Error");
        }
    }

    private void ExecuteDeleteItem(object? param)
    {
        CredentialItemViewModel? item = (param as CredentialItemViewModel) ?? SelectedItem;
        if (item is null || _session.CurrentProfile is null) return;

        bool confirm = _dialogs.ShowConfirm(
            $"Are you sure you want to delete '{item.Name}'?\n\nThis cannot be undone. If you delete a passkey without a backup, you will lose access to that service.",
            "Delete Credential",
            "Delete Permanently",
            isDestructive: true);

        if (!confirm) return;

        if (item.IsPasskey && item.PasskeyData is not null)
        {
            _session.CurrentProfile.Data.FidoKeys.Remove(item.PasskeyData);
            _session.AddAuditEvent("Passkey", "Success", $"Deleted passkey for '{item.PasskeyData.RpId}'.");
        }
        else if (!item.IsPasskey && item.TotpData is not null)
        {
            _session.CurrentProfile.Data.TotpEntries.Remove(item.TotpData);
            _session.AddAuditEvent("Totp", "Success", $"Deleted TOTP account '{item.Name}'.");
        }

        _session.Save();
        LoadItems();
    }

    private void ExecuteNewPasskey()
    {
        if (_session.CurrentProfile is null) return;

        var options = _dialogs.ShowCreatePasskeyDialog();
        if (options is null) return;

        var helper = new System.Windows.Interop.WindowInteropHelper(Application.Current.MainWindow);

        try
        {
            if (options.Value.UsePlatform)
            {
                // Register via Windows Hello Platform Authenticator
                FidoKeyRecord record = _session.WebAuthn.RegisterCredential(
                    helper.Handle,
                    _session.CurrentProfile.Metadata.Id,
                    options.Value.DisplayName,
                    usePlatformAuthenticator: true);

                record.RpId = options.Value.RpId;
                record.UserName = options.Value.UserName;
                _session.CurrentProfile.Data.FidoKeys.Add(record);
            }
            else
            {
                // Register software passkey
                byte[] userId = _session.CurrentProfile.Metadata.Id.ToByteArray();
                var swCred = _session.SoftwarePasskeys.Create(
                    options.Value.RpId,
                    options.Value.RpId,
                    userId,
                    options.Value.UserName,
                    options.Value.DisplayName,
                    _session.CurrentProfile.Metadata.Id);

                var record = new FidoKeyRecord
                {
                    Name = options.Value.DisplayName,
                    CredentialId = Convert.ToBase64String(swCred.CredentialId),
                    PublicKeyCoseBase64 = "",
                    Type = "Software virtual passkey",
                    Transport = "Internal software vault",
                    RpId = options.Value.RpId,
                    UserName = options.Value.UserName,
                    SignCounter = swCred.SignCount
                };
                _session.CurrentProfile.Data.FidoKeys.Add(record);
            }

            _session.Save();
            _session.AddAuditEvent("Passkey", "Success", $"Registered passkey for '{options.Value.RpId}'.");
            LoadItems();
            _dialogs.ShowAlert($"Passkey registered successfully for '{options.Value.RpId}'!", "Passkey Created");
        }
        catch (Exception ex)
        {
            _session.AddAuditEvent("Passkey", "Failure", $"Passkey registration failed for '{options.Value.RpId}': {ex.Message}");
            _dialogs.ShowError($"Failed to register passkey:\n{ex.Message}", "Registration Failed");
        }
    }

    private void ExecuteNewTotpManual()
    {
        if (_session.CurrentProfile is null) return;

        TotpEntry? entry = _dialogs.ShowAddTotpManual();
        if (entry is null) return;

        _session.CurrentProfile.Data.TotpEntries.Add(entry);
        _session.Save();
        _session.AddAuditEvent("Totp", "Success", $"Added manual TOTP account '{entry.DisplayName}'.");
        LoadItems();
    }

    private void ExecuteSnipeScreenQr()
    {
        if (_session.CurrentProfile is null) return;

        try
        {
            string? uri = _qrCapture.ScanScreens();
            if (string.IsNullOrWhiteSpace(uri))
            {
                _dialogs.ShowAlert("No TOTP QR code was found on any active screen.", "QR Scanner");
                return;
            }

            TotpEntry entry = TotpService.ParseOtpAuthUri(uri);
            _session.CurrentProfile.Data.TotpEntries.Add(entry);
            _session.Save();
            _session.AddAuditEvent("Totp", "Success", $"Imported TOTP account '{entry.DisplayName}' from screen scan.");
            LoadItems();
            _dialogs.ShowAlert($"Imported TOTP account:\n{entry.DisplayName}", "Screen QR Decoded");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Screen QR scan failed: {ex.Message}");
        }
    }

    private void ExecuteImportQrFile()
    {
        if (_session.CurrentProfile is null) return;

        var ofd = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Import QR Code Image",
            Filter = "Images (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|All Files (*.*)|*.*"
        };
        if (ofd.ShowDialog() != true) return;

        try
        {
            string? text = _qrCapture.DecodeFile(ofd.FileName);
            if (string.IsNullOrWhiteSpace(text) || !text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                _dialogs.ShowAlert("No valid otpauth:// QR code was found in that image file.", "QR Decode Error");
                return;
            }

            TotpEntry entry = TotpService.ParseOtpAuthUri(text);
            _session.CurrentProfile.Data.TotpEntries.Add(entry);
            _session.Save();
            _session.AddAuditEvent("Totp", "Success", $"Imported TOTP account '{entry.DisplayName}' from file.");
            LoadItems();
            _dialogs.ShowAlert($"Imported TOTP account:\n{entry.DisplayName}", "QR Image Decoded");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Failed to decode QR image: {ex.Message}");
        }
    }
}

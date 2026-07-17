using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using DarksFIDO2.Core;
using DarksFIDO2.Core.Interop;
using DarksFIDO2.Core.Passkeys;
using DarksFIDO2.Core.Security;
using DarksFIDO2.Core.Storage;
using Microsoft.Win32;
using ZXing;
using ZXing.Common;
using Drawing = System.Drawing;
using DrawingImaging = System.Drawing.Imaging;

namespace DarksFIDO2.App;

public partial class MainWindow : Window
{
    private const int HotkeyId = 0xD2F2;
    private const string VirtualProviderAaguid = "07f654b1-1d48-45b8-ac72-4915efa620c1";
    private const string GitHubUrl = "https://github.com/darkbyte-JS";
    private readonly AppPaths _paths = new();
    private readonly TpmService _tpm = new();
    private readonly WebAuthnService _webauthn = new();
    private readonly PasskeyProviderService _passkeyProvider = new();
    private readonly PasskeyProviderContext _passkeyContext = new();
    private readonly SoftwarePasskeyStore _providerStore = new();
    private readonly VaultRepository _repository;
    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly List<(TextBlock Code, TextBlock Countdown, ProgressBar Progress, TotpEntry Entry)> _totpViews = [];
    private UnlockedProfile? _profile;
    private CliBridgeServer? _cliServer;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private string? _keyfilePath;
    private bool _tpm12Acknowledged;
    private bool _integrityWarningShown;
    private bool? _trustedSignature;
    private int _pageVersion;
    private DateTime _lastProviderStoreWriteUtc;
    private DateTimeOffset _lastProfileContextRefreshUtc;
    private string? _providerSyncError;
    private string? _lastCopiedTotp;
    private bool _unlockInProgress;

    public MainWindow()
    {
        _repository = new VaultRepository(_paths, _tpm);
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        SourceInitialized += MainWindow_SourceInitialized;
        Closed += MainWindow_Closed;
        PreviewMouseDown += (_, _) => _lastActivity = DateTimeOffset.UtcNow;
        PreviewKeyDown += MainWindow_PreviewKeyDown;
        _clock.Tick += Clock_Tick;
        _clock.Start();
        _cliServer = new CliBridgeServer(() => _profile);
        _cliServer.Start();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        LoadProfiles();
        await Task.Yield();
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(120));
        fade.Completed += (_, _) =>
        {
            WelcomeLayer.Visibility = Visibility.Collapsed;
            GateLayer.Opacity = 0;
            GateLayer.Visibility = Visibility.Visible;
            GateLayer.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(140)));
            _ = WarnIfUnsignedAsync();
        };
        WelcomeLayer.BeginAnimation(OpacityProperty, fade);
    }

    private void LoadProfiles(Guid? select = null)
    {
        ProfileIndex index;
        try { index = _repository.LoadIndex(); }
        catch (Exception ex)
        {
            GateError.Text = ex.Message;
            ProfilePicker.ItemsSource = null;
            return;
        }
        ProfilePicker.ItemsSource = index.Profiles;
        Guid? desired = select ?? index.LastProfileId;
        ProfilePicker.SelectedItem = index.Profiles.FirstOrDefault(x => x.Id == desired) ?? index.Profiles.FirstOrDefault();
        bool any = index.Profiles.Count > 0;
        GateTitle.Text = any ? "Unlock your vault" : "Create your first vault";
        GateSubtitle.Text = any ? "Select a profile and enter its independent credentials." : "No local vault exists yet. Create an encrypted profile to begin.";
        PinBox.IsEnabled = any;
        GateError.Text = "";
    }

    private void ProfilePicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ProfileSummary? selected = ProfilePicker.SelectedItem as ProfileSummary;
        bool required = selected?.KeyfileRequired == true;
        KeyfileRow.Visibility = required ? Visibility.Visible : Visibility.Collapsed;
        RecoveryButton.Visibility = required ? Visibility.Visible : Visibility.Collapsed;
        KeyfilePathBox.Text = required ? _keyfilePath ?? "No keyfile selected" : "";
        GateError.Text = "";
    }

    private void ChooseKeyfile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select the master keyfile", Filter = "Darks FIDO2 keyfiles (*.dfkey)|*.dfkey|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) == true)
        {
            _keyfilePath = dialog.FileName;
            KeyfilePathBox.Text = dialog.FileName;
        }
    }

    private void PinBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        Unlock_Click(sender, e);
    }

    private async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if (_unlockInProgress) return;
        if (ProfilePicker.SelectedItem is not ProfileSummary selected) { CreateProfile_Click(sender, e); return; }
        byte[]? keyfile = null;
        UnlockedProfile? opened = null;
        try
        {
            SetUnlockBusy(true, "Unlocking and verifying your encrypted vault…");
            GateError.Text = "";
            if (selected.KeyfileRequired)
            {
                if (string.IsNullOrWhiteSpace(_keyfilePath) || !File.Exists(_keyfilePath))
                    throw new InvalidOperationException("Select the required master keyfile before unlocking.");
                keyfile = SecureFile.ReadAllBytes(_keyfilePath, 1024 * 1024);
            }
            string pin = PinBox.Password;
            byte[]? unlockKeyfile = keyfile;
            opened = await Task.Run(() => _repository.Unlock(selected.Id, pin, unlockKeyfile));
            _profile = opened;
            opened = null;
            PinBox.Clear();
            await OpenShellAsync();
        }
        catch (Exception ex)
        {
            DisposeFailedUnlock();
            GateError.Text = ex.Message;
            PinBox.Clear();
        }
        finally
        {
            opened?.Dispose();
            if (keyfile is not null) CryptographicOperations.ZeroMemory(keyfile);
            SetUnlockBusy(false);
        }
    }

    private async void Recovery_Click(object sender, RoutedEventArgs e)
    {
        if (_unlockInProgress) return;
        if (ProfilePicker.SelectedItem is not ProfileSummary selected) return;
        string? code = Dialogs.Prompt(this, "Recovery unlock", "Enter the one-time recovery code. Your PIN is still required.", secret: true);
        if (code is null) return;
        UnlockedProfile? opened = null;
        try
        {
            SetUnlockBusy(true, "Verifying the recovery code and unlocking…");
            GateError.Text = "";
            string pin = PinBox.Password;
            opened = await Task.Run(() => _repository.UnlockWithRecovery(selected.Id, pin, code));
            _profile = opened;
            opened = null;
            PinBox.Clear();
            _keyfilePath = null;
            await OpenShellAsync();
        }
        catch (Exception ex)
        {
            DisposeFailedUnlock();
            GateError.Text = ex.Message;
            PinBox.Clear();
        }
        finally
        {
            opened?.Dispose();
            SetUnlockBusy(false);
        }
    }

    private async void CreateProfile_Click(object sender, RoutedEventArgs e)
    {
        if (_unlockInProgress) return;
        var wizard = new ProfileSetupWindow(this);
        if (wizard.ShowDialog() != true) return;
        byte[]? keyfile = null;
        string? keyfilePath = null;
        string? recoveryCode = null;
        UnlockedProfile? opened = null;
        try
        {
            if (wizard.UseKeyfile)
            {
                var save = new SaveFileDialog
                {
                    Title = "Choose a safe location for the master keyfile",
                    Filter = "Darks FIDO2 keyfile (*.dfkey)|*.dfkey",
                    AddExtension = true,
                    OverwritePrompt = true
                };
                if (save.ShowDialog(this) != true) return;
                keyfile = VaultCryptography.GenerateKeyfile();
                SecureFile.AtomicWrite(save.FileName, keyfile);
                keyfilePath = save.FileName;
                recoveryCode = VaultCryptography.GenerateRecoveryCode();
                MessageBox.Show(this,
                    "Save this recovery code separately. It can replace a lost keyfile only when combined with your PIN:\n\n" + recoveryCode +
                    "\n\nIf both the keyfile and recovery code are lost, the vault cannot be unlocked.",
                    "One-time recovery code", MessageBoxButton.OK, MessageBoxImage.Warning);
                var recoverySave = new SaveFileDialog { Title = "Optional: save the recovery code", Filter = "Text file (*.txt)|*.txt", AddExtension = true };
                if (recoverySave.ShowDialog(this) == true)
                    File.WriteAllText(recoverySave.FileName, "Darks FIDO2 recovery code\r\nProfile: " + wizard.ProfileName + "\r\n\r\n" + recoveryCode, new UTF8Encoding(false));
            }
            SetUnlockBusy(true, "Creating and encrypting your new vault…");
            ProfileCreationRequest request = new(wizard.ProfileName, wizard.Pin, keyfile, recoveryCode);
            opened = await Task.Run(() => _repository.CreateProfile(request));
            _profile = opened;
            opened = null;
            _keyfilePath = keyfilePath;
            await OpenShellAsync();
        }
        catch (Exception ex)
        {
            DisposeFailedUnlock();
            MessageBox.Show(this, ex.Message, "Profile creation failed", MessageBoxButton.OK, MessageBoxImage.Error);
            LoadProfiles();
        }
        finally
        {
            opened?.Dispose();
            if (keyfile is not null) CryptographicOperations.ZeroMemory(keyfile);
            SetUnlockBusy(false);
        }
    }

    private async Task OpenShellAsync()
    {
        UnlockedProfile? profile = _profile;
        if (profile is null) return;
        UnlockStatusText.Text = "Activating the selected passkey profile…";
        TpmStatus status = await Task.Run(() =>
        {
            _passkeyContext.SetActiveProfile(profile.Metadata.Id);
            SyncProviderCredentials(force: true);
            return _tpm.Detect();
        });
        if (!ReferenceEquals(_profile, profile)) return;
        _lastProfileContextRefreshUtc = DateTimeOffset.UtcNow;
        WindowState = WindowState.Maximized;
        ThemeManager.Apply(profile.Data.Settings.Theme);
        AuroraBackground.Opacity = profile.Data.Settings.Theme == AppTheme.Aurora ? 1 : 0;
        GateLayer.Visibility = Visibility.Collapsed;
        Shell.Opacity = 0;
        Shell.Visibility = Visibility.Visible;
        Shell.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300)));
        SideProfileName.Text = profile.Data.ProfileName;
        SecurityModeText.Text = profile.Metadata.DeviceProtection == DeviceProtection.Tpm
            ? $"TPM-bound vault · {status.Version}"
            : status.Mode == TpmMode.None
                ? "DPAPI + PIN-derived key · TPM unavailable"
                : $"DPAPI-wrapped vault · TPM {status.Version} available for new hardware keys";
        _lastActivity = DateTimeOffset.UtcNow;
        ProtectWindowFromCapture(true);
        _ = RenderFidoAsync();
    }

    private void SetUnlockBusy(bool busy, string? status = null)
    {
        _unlockInProgress = busy;
        ProfilePicker.IsEnabled = !busy;
        PinBox.IsEnabled = !busy && ProfilePicker.Items.Count > 0;
        KeyfileRow.IsEnabled = !busy;
        UnlockButton.IsEnabled = !busy;
        RecoveryButton.IsEnabled = !busy;
        CreateProfileButton.IsEnabled = !busy;
        if (!string.IsNullOrWhiteSpace(status)) UnlockStatusText.Text = status;
        UnlockProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        Mouse.OverrideCursor = busy ? Cursors.Wait : null;
    }

    private void DisposeFailedUnlock()
    {
        if (_profile is null) return;
        try { _passkeyContext.Clear(_profile.Metadata.Id); } catch { }
        _profile.Dispose();
        _profile = null;
    }

    private void LockVault(bool minimize = false)
    {
        ClearSensitiveClipboard();
        _pageVersion++;
        if (_profile is not null)
        {
            _passkeyContext.Clear(_profile.Metadata.Id);
            try
            {
                _profile.Data.AuditLog.Add(new AuditEvent { Type = "Authentication", Message = minimize ? "Quick-lock hotkey used." : "Profile locked." });
                _repository.Save(_profile);
            }
            catch { }
            _profile.Dispose();
            _profile = null;
        }
        _totpViews.Clear();
        ContentPanel.Children.Clear();
        Shell.Visibility = Visibility.Collapsed;
        GateLayer.Visibility = Visibility.Visible;
        PinBox.Clear();
        GateError.Text = "Vault locked. Decrypted key material was cleared from memory.";
        ProtectWindowFromCapture(false);
        LoadProfiles();
        if (minimize) WindowState = WindowState.Minimized;
    }

    private async void Dashboard_Click(object sender, RoutedEventArgs e) => await RenderDashboardAsync();
    private async void Fido_Click(object sender, RoutedEventArgs e) => await RenderFidoAsync();
    private void Totp_Click(object sender, RoutedEventArgs e) => RenderTotp();
    private void Tpm_Click(object sender, RoutedEventArgs e) => RenderTpm();
    private void Settings_Click(object sender, RoutedEventArgs e) => RenderSettings();
    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault();

    private async Task RenderDashboardAsync()
    {
        if (_profile is null) return;
        SyncProviderCredentials();
        int pageVersion = ++_pageVersion;
        SetPage("Dashboard", "Security at a glance");
        ContentPanel.Children.Clear();
        _totpViews.Clear();
        if (_providerSyncError is not null)
            ContentPanel.Children.Add(Banner("Virtual passkey sync needs attention", _providerSyncError, "danger"));
        int pendingRegistrations = _profile.Data.FidoKeys.Count(k => k.RegistrationStatus == PasskeyRegistrationStatus.Pending);
        if (pendingRegistrations > 0)
            ContentPanel.Children.Add(Banner(
                $"{pendingRegistrations} passkey registration{(pendingRegistrations == 1 ? " is" : "s are")} awaiting site confirmation",
                "The private key was created, but the website has not yet proven that it accepted the public key. Check the website's passkey list; remove the pending entry here if Google or another site reported an error.",
                "warning"));
        if (_profile.Data.FidoKeys.Count < 2)
            ContentPanel.Children.Add(Banner("Backup key recommended", "Register at least two FIDO2 keys so one can be stored as a recovery key.", "warning"));
        if (!HasTrustedSignature())
            ContentPanel.Children.Add(Banner("Development signature", "This build is signed with a local development certificate or is not trusted by this account. Use a publicly trusted release certificate before distribution.", "danger"));

        var stats = new UniformGrid { Columns = 3, Margin = new Thickness(0, 0, 0, 24) };
        stats.Children.Add(StatCard(_profile.Data.FidoKeys.Count.ToString(), "Registered FIDO2 credentials"));
        stats.Children.Add(StatCard(_profile.Data.TotpEntries.Count.ToString(), "Encrypted TOTP accounts"));
        TpmStatus tpm = _tpm.Detect();
        stats.Children.Add(StatCard(tpm.Mode == TpmMode.None ? "None" : tpm.Version, "Detected TPM mode"));
        ContentPanel.Children.Add(stats);

        ContentPanel.Children.Add(SectionTitle("Available authenticators", "Windows WebAuthn API v" + _webauthn.ApiVersion));
        Border loadingDevices = EmptyCard("Checking authenticators…", "Windows Hello and external-device discovery is running in the background.");
        ContentPanel.Children.Add(loadingDevices);
        try
        {
            IReadOnlyList<AuthenticatorInfo> authenticators = await Task.Run(_webauthn.EnumerateAuthenticators);
            if (_profile is null || pageVersion != _pageVersion) return;
            ContentPanel.Children.Remove(loadingDevices);
            if (_webauthn.IsPlatformAuthenticatorAvailable())
                ContentPanel.Children.Add(InfoCard("Windows Hello", "Built-in platform FIDO2 authenticator · Ready", "No USB key is required. Supported websites can use Windows Hello passkeys directly."));
            if (authenticators.Count == 0) ContentPanel.Children.Add(EmptyCard("No currently discoverable authenticators", "Insert or unlock a FIDO2 key, then refresh."));
            foreach (AuthenticatorInfo item in authenticators)
                ContentPanel.Children.Add(InfoCard(item.Name, $"{item.Kind} · {(item.IsLocked ? "Locked" : "Ready")}", item.Id.Length > 24 ? item.Id[..24] + "…" : item.Id));
        }
        catch (Exception ex)
        {
            if (_profile is null || pageVersion != _pageVersion) return;
            ContentPanel.Children.Remove(loadingDevices);
            ContentPanel.Children.Add(Banner("Authenticator query failed", ex.Message, "danger"));
        }
        var actions = new WrapPanel { Margin = new Thickness(0, 8, 0, 24) };
        actions.Children.Add(ActionButton("Register a passkey", RegisterFido_Click, true));
        actions.Children.Add(ActionButton("Refresh devices", async (_, _) => await RenderDashboardAsync()));
        ContentPanel.Children.Add(actions);

        ContentPanel.Children.Add(SectionTitle("Profile registrations", "Credentials created for Darks FIDO2 on this profile"));
        if (_profile.Data.FidoKeys.Count == 0) ContentPanel.Children.Add(EmptyCard("No passkeys registered yet", "Choose Windows Hello for a built-in platform passkey, or use an external USB/NFC/BLE key."));
        foreach (FidoKeyRecord item in _profile.Data.FidoKeys.ToArray()) ContentPanel.Children.Add(FidoCard(item));
    }

    private async Task RenderFidoAsync()
    {
        if (_profile is null) return;
        SyncProviderCredentials();
        int pageVersion = ++_pageVersion;
        SetPage("Passkeys & FIDO2", "Passwordless authentication with Windows Hello or external security keys");
        ContentPanel.Children.Clear();
        _totpViews.Clear();
        if (_providerSyncError is not null)
            ContentPanel.Children.Add(Banner("Virtual passkey sync needs attention", _providerSyncError, "danger"));

        ContentPanel.Children.Add(Banner(
            "Passkeys that tell the truth about their state",
            "A website validates a new public key after the authenticator creates its private key. New virtual passkeys stay Pending until their first successful sign-in; if Google rejects registration, remove the pending entry here to delete the local key and Windows metadata.",
            "success"));

        PasskeyProviderStatus provider = _passkeyProvider.GetStatus();
        string providerKind = provider.State == PasskeyProviderState.Enabled ? "success" :
            provider.State == PasskeyProviderState.RegisteredDisabled || provider.State == PasskeyProviderState.NotRegistered ? "warning" : "danger";
        string providerTitle = provider.State switch
        {
            PasskeyProviderState.Enabled => "Virtual passkey provider active",
            PasskeyProviderState.RegisteredDisabled => "One-time Windows approval required",
            PasskeyProviderState.NotRegistered => "Virtual passkey provider ready",
            PasskeyProviderState.Missing => "Virtual passkey companion missing",
            _ => "Windows passkey plugin unavailable"
        };
        ContentPanel.Children.Add(Banner(providerTitle, provider.Detail, providerKind));
        var providerActions = new WrapPanel { Margin = new Thickness(0, 8, 0, 24) };
        if (provider.State == PasskeyProviderState.NotRegistered)
            providerActions.Children.Add(ActionButton("Register virtual passkey", RegisterPasskeyProvider_Click, true));
        if (provider.State is PasskeyProviderState.RegisteredDisabled or PasskeyProviderState.Enabled)
            providerActions.Children.Add(ActionButton("Open Windows passkey settings", OpenPasskeySettings_Click, provider.State == PasskeyProviderState.RegisteredDisabled));
        providerActions.Children.Add(ActionButton("Refresh provider status", async (_, _) => await RenderFidoAsync()));
        ContentPanel.Children.Add(providerActions);

        bool helloAvailable = _webauthn.IsPlatformAuthenticatorAvailable();
        ContentPanel.Children.Add(SectionTitle("Choose an authenticator", "Private keys remain inside Windows Hello or the external authenticator"));
        ContentPanel.Children.Add(InfoCard(
            "Windows Hello passkey",
            helloAvailable ? "Built-in FIDO2 authenticator · Ready" : "Built-in FIDO2 authenticator · Not configured",
            helloAvailable ? "No USB key is required." : "Configure Windows Hello in Settings > Accounts > Sign-in options."));
        ContentPanel.Children.Add(InfoCard(
            "External security key",
            "USB · NFC · Bluetooth",
            "Use a roaming FIDO2 key for portable authentication and keep a second key as backup."));

        var primaryActions = new WrapPanel { Margin = new Thickness(0, 12, 0, 24) };
        primaryActions.Children.Add(ActionButton("Register a passkey", RegisterFido_Click, true));
        primaryActions.Children.Add(ActionButton("Refresh authenticators", async (_, _) => await RenderFidoAsync()));
        ContentPanel.Children.Add(primaryActions);

        ContentPanel.Children.Add(SectionTitle("Connected authenticators", "Discovered through the Windows WebAuthn API"));
        Border loading = EmptyCard("Checking authenticators…", "Discovery runs in the background so the app remains responsive.");
        ContentPanel.Children.Add(loading);
        try
        {
            IReadOnlyList<AuthenticatorInfo> authenticators = await Task.Run(_webauthn.EnumerateAuthenticators);
            if (_profile is null || pageVersion != _pageVersion) return;
            ContentPanel.Children.Remove(loading);
            if (authenticators.Count == 0)
                ContentPanel.Children.Add(EmptyCard("No external authenticator currently connected", "Windows Hello can still be used when it is configured. Insert or unlock an external key, then refresh."));
            foreach (AuthenticatorInfo item in authenticators)
                ContentPanel.Children.Add(InfoCard(item.Name, $"{item.Kind} · {(item.IsLocked ? "Locked" : "Ready")}", item.Id.Length > 24 ? item.Id[..24] + "…" : item.Id));
        }
        catch (Exception ex)
        {
            if (_profile is null || pageVersion != _pageVersion) return;
            ContentPanel.Children.Remove(loading);
            ContentPanel.Children.Add(Banner("Authenticator query failed", ex.Message, "danger"));
        }

        ContentPanel.Children.Add(SectionTitle("Your Darks FIDO2 registrations", "Passkeys registered for this encrypted profile"));
        if (_profile.Data.FidoKeys.Count == 0)
            ContentPanel.Children.Add(EmptyCard("No passkeys registered yet", "Register Windows Hello or an external security key to begin."));
        foreach (FidoKeyRecord item in _profile.Data.FidoKeys.ToArray())
            ContentPanel.Children.Add(FidoCard(item));

        ContentPanel.Children.Add(Banner(
            "Advanced hardware features are separate",
            "TPM key generation is an optional advanced tool. It does not replace FIDO2 passkeys and is no longer presented as the main feature.",
            "warning"));
    }

    private async void RegisterPasskeyProvider_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Task.Run(_passkeyProvider.Register);
            _profile?.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = "Registered the Darks FIDO2 virtual passkey provider with Windows." });
            if (_profile is not null) _repository.Save(_profile);
            MessageBox.Show(this,
                "The provider is registered. Windows requires one approval: open Passkey settings, choose Advanced options, and enable Darks FIDO2. After that, Google and other sites can activate it automatically.",
                "Virtual passkey registered", MessageBoxButton.OK, MessageBoxImage.Information);
            _passkeyProvider.OpenWindowsSettings();
            await RenderFidoAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Provider registration failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OpenPasskeySettings_Click(object sender, RoutedEventArgs e)
    {
        try { _passkeyProvider.OpenWindowsSettings(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Unable to open Windows Settings", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void RegisterFido_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return;
        bool? usePlatform = Dialogs.ChooseFidoRegistration(this, _webauthn.IsPlatformAuthenticatorAvailable());
        if (usePlatform is null) return;
        if (usePlatform == true && !_webauthn.IsPlatformAuthenticatorAvailable())
        {
            MessageBox.Show(this, "Windows Hello is not configured. Open Windows Settings > Accounts > Sign-in options, configure Hello, then refresh this page.", "Windows Hello unavailable", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string? name = Dialogs.Prompt(this, "Register passkey", "Give this credential a local name, then follow the Windows Security prompt.", usePlatform == true ? "Windows Hello" : "Backup security key");
        if (string.IsNullOrWhiteSpace(name)) return;
        try
        {
            FidoKeyRecord key = _webauthn.RegisterCredential(new WindowInteropHelper(this).Handle, _profile.Metadata.Id, name.Trim(), usePlatform == true);
            _profile.Data.FidoKeys.Add(key);
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"Registered FIDO2 credential: {key.Name}." });
            _repository.Save(_profile);
            _ = RenderFidoAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Registration did not complete", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private Border FidoCard(FidoKeyRecord item)
    {
        var content = new StackPanel();
        var titleRow = new DockPanel();
        var status = new Border
        {
            Style = (Style)FindResource("StatusPill"),
            Background = (Brush)FindResource(item.RegistrationStatus == PasskeyRegistrationStatus.Pending ? "WarningSurfaceBrush" : "SuccessSurfaceBrush"),
            BorderBrush = (Brush)FindResource(item.RegistrationStatus == PasskeyRegistrationStatus.Pending ? "WarningBrush" : "SuccessBrush"),
            Child = new TextBlock
            {
                Text = item.RegistrationStatus == PasskeyRegistrationStatus.Pending ? "Pending site confirmation" : "Confirmed",
                Foreground = (Brush)FindResource(item.RegistrationStatus == PasskeyRegistrationStatus.Pending ? "WarningBrush" : "SuccessBrush"),
                FontWeight = FontWeights.SemiBold,
                FontSize = 12
            }
        };
        DockPanel.SetDock(status, Dock.Right);
        titleRow.Children.Add(status);
        titleRow.Children.Add(new TextBlock { Text = item.Name, FontSize = 18, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis });
        content.Children.Add(titleRow);
        content.Children.Add(new TextBlock { Text = $"{item.Type} · {item.Transport} · Added {item.AddedUtc.LocalDateTime:g}", Foreground = Muted(), Margin = new Thickness(0, 4, 0, 4) });
        string identity = string.IsNullOrWhiteSpace(item.RpId)
            ? ""
            : $"{item.RpId}{(string.IsNullOrWhiteSpace(item.UserName) ? "" : " · " + item.UserName)} · ";
        content.Children.Add(new TextBlock { Text = $"{identity}AAGUID {item.Aaguid} · Counter {item.SignCounter} · Resident key {(item.ResidentKey ? "yes" : "not reported")}", Foreground = Muted(), FontSize = 12, TextWrapping = TextWrapping.Wrap });
        if (item.RegistrationStatus == PasskeyRegistrationStatus.Pending)
            content.Children.Add(new TextBlock
            {
                Text = "If the website displayed an error and this passkey is absent from its account settings, remove this pending registration. Darks FIDO2 cannot receive the website's final accept/reject result from Windows.",
                Foreground = (Brush)FindResource("WarningBrush"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 12, 0, 0)
            });
        var buttons = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
        bool providerCredential = item.AuthenticatorId == "DarksFIDO2.Provider";
        if (!providerCredential) buttons.Children.Add(ActionButton("Verify health", (_, _) => VerifyFido(item)));
        buttons.Children.Add(ActionButton("Rename", (_, _) => RenameFido(item)));
        if (providerCredential)
        {
            if (item.RegistrationStatus == PasskeyRegistrationStatus.Pending)
                buttons.Children.Add(ActionButton("Mark confirmed", (_, _) => ConfirmProviderFido(item), true));
            buttons.Children.Add(ActionButton(
                item.RegistrationStatus == PasskeyRegistrationStatus.Pending ? "Remove rejected registration" : "Remove passkey",
                (_, _) => RemoveProviderFido(item)));
            buttons.Children.Add(ActionButton("Windows settings", OpenPasskeySettings_Click));
        }
        else
            buttons.Children.Add(ActionButton("Remove", (_, _) => RemoveFido(item)));
        content.Children.Add(buttons);
        return Card(content);
    }

    private void ConfirmProviderFido(FidoKeyRecord item)
    {
        if (_profile is null) return;
        try
        {
            byte[] credentialId = Convert.FromBase64String(item.CredentialId);
            if (!_providerStore.ConfirmRegistration(_profile.Metadata.Id, credentialId))
                throw new InvalidOperationException("The provider credential no longer exists.");
            item.RegistrationStatus = PasskeyRegistrationStatus.Confirmed;
            item.ConfirmedUtc = DateTimeOffset.UtcNow;
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"User confirmed site registration for {item.Name}." });
            _repository.Save(_profile);
            _ = RenderFidoAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Unable to confirm passkey", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void RemoveProviderFido(FidoKeyRecord item)
    {
        if (_profile is null) return;
        string message = item.RegistrationStatus == PasskeyRegistrationStatus.Pending
            ? "Remove this pending passkey because the website rejected or did not save it?\n\nThis deletes the private key, the encrypted provider record, and its Windows autofill metadata. Confirm first that the passkey is not listed on the website."
            : "Permanently remove this virtual passkey from Darks FIDO2 and Windows autofill metadata?\n\nRemove it from the website account first so you do not leave an unusable account entry.";
        if (!Dialogs.Confirm(this, "Remove virtual passkey", message)) return;

        string? metadataWarning = null;
        try
        {
            byte[] credentialId = Convert.FromBase64String(item.CredentialId);
            SoftwarePasskeyCredential? credential = _providerStore.Find(_profile.Metadata.Id, credentialId);
            if (credential is not null)
            {
                if (!_providerStore.Remove(_profile.Metadata.Id, credentialId))
                    throw new InvalidOperationException("The provider key could not be removed.");
                try { PasskeyProviderService.RemoveCredentialMetadata(credential); }
                catch (Exception ex) { metadataWarning = ex.Message; }
            }
            _profile.Data.FidoKeys.Remove(item);
            _profile.Data.AuditLog.Add(new AuditEvent
            {
                Type = "FIDO2",
                Message = $"Removed virtual passkey {item.Name}.",
                Outcome = metadataWarning is null ? "Success" : "Partial"
            });
            _repository.Save(_profile);
            _lastProviderStoreWriteUtc = File.Exists(_providerStore.StorePath) ? File.GetLastWriteTimeUtc(_providerStore.StorePath) : DateTime.MinValue;
            if (metadataWarning is not null)
                MessageBox.Show(this,
                    "The private key and encrypted record were removed, but Windows did not remove its cached autofill metadata:\n\n" + metadataWarning +
                    "\n\nOpen Windows passkey settings to remove the stale entry.",
                    "Windows metadata needs cleanup", MessageBoxButton.OK, MessageBoxImage.Warning);
            _ = RenderFidoAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Passkey was not removed", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void VerifyFido(FidoKeyRecord item)
    {
        if (_profile is null) return;
        try
        {
            item.SignCounter = _webauthn.VerifyCredential(new WindowInteropHelper(this).Handle, item);
            item.LastUsedUtc = item.LastVerifiedUtc = DateTimeOffset.UtcNow;
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"Verified key health: {item.Name}." });
            _repository.Save(_profile);
            _ = RenderFidoAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Verification did not complete", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void RenameFido(FidoKeyRecord item)
    {
        if (_profile is null) return;
        string? name = Dialogs.Prompt(this, "Rename key", "New local name", item.Name);
        if (string.IsNullOrWhiteSpace(name)) return;
        if (name.Trim().Length > 256) { MessageBox.Show(this, "Key names are limited to 256 characters."); return; }
        item.Name = name.Trim();
        _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"Renamed key to {item.Name}." });
        _repository.Save(_profile); _ = RenderFidoAsync();
    }

    private void RemoveFido(FidoKeyRecord item)
    {
        if (_profile is null || !Dialogs.Confirm(this, "Remove key", "Remove this Darks FIDO2 registration? Platform credentials will also be deleted through WebAuthn when Windows permits it. External keys may require deletion through the authenticator vendor's management tool.")) return;
        try { if (item.Type.Contains("Platform", StringComparison.OrdinalIgnoreCase)) _webauthn.DeletePlatformCredential(item); }
        catch (Exception ex) { MessageBox.Show(this, "Windows did not delete the authenticator credential: " + ex.Message + "\n\nThe local registration will still be removed.", "Credential deletion", MessageBoxButton.OK, MessageBoxImage.Warning); }
        _profile.Data.FidoKeys.Remove(item);
        _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"Removed local registration: {item.Name}." });
        _repository.Save(_profile); _ = RenderFidoAsync();
    }

    private void RenderTotp()
    {
        if (_profile is null) return;
        _pageVersion++;
        SetPage("2FA codes", "RFC 6238 codes computed locally — seeds never leave the vault");
        ContentPanel.Children.Clear(); _totpViews.Clear();
        var actions = new WrapPanel { Margin = new Thickness(0, 0, 0, 18) };
        actions.Children.Add(ActionButton("Add account manually", AddTotpManual_Click, true));
        actions.Children.Add(ActionButton("Scan QR from screen", ScanScreenQr_Click));
        actions.Children.Add(ActionButton("Import QR image", ImportQr_Click));
        actions.Children.Add(ActionButton("Add otpauth URI", AddTotp_Click));
        actions.Children.Add(ActionButton("Paste URI", PasteTotp_Click));
        ContentPanel.Children.Add(actions);
        if (_profile.Data.TotpEntries.Count == 0) ContentPanel.Children.Add(EmptyCard("No TOTP accounts", "Import an otpauth:// URI or a QR-code image. Seeds are encrypted inside this profile."));
        foreach (TotpEntry entry in _profile.Data.TotpEntries.ToArray())
        {
            TotpCode current = TotpService.GetCode(entry);
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition()); grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var left = new StackPanel();
            left.Children.Add(new TextBlock { Text = entry.DisplayName, FontSize = 17, FontWeight = FontWeights.SemiBold });
            var code = new TextBlock { Text = FormatCode(current.Code), FontFamily = new FontFamily("Cascadia Mono"), FontSize = 32, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 10, 0, 4) };
            var countdown = new TextBlock { Text = $"Refreshes in {current.SecondsRemaining}s · {entry.Period}s interval · {entry.Algorithm}", Foreground = Muted(), FontSize = 12 };
            var progress = new ProgressBar { Minimum = 0, Maximum = 1, Value = current.Progress, Height = 5, Margin = new Thickness(0, 9, 18, 0), Foreground = (Brush)FindResource("AccentBrush"), Background = (Brush)FindResource("PanelAltBrush") };
            left.Children.Add(code); left.Children.Add(countdown); left.Children.Add(progress); grid.Children.Add(left);
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            buttons.Children.Add(ActionButton("Copy", (_, _) => CopyTotp(entry)));
            buttons.Children.Add(ActionButton("Delete", (_, _) => DeleteTotp(entry)));
            Grid.SetColumn(buttons, 1); grid.Children.Add(buttons);
            ContentPanel.Children.Add(Card(grid));
            _totpViews.Add((code, countdown, progress, entry));
        }
    }

    private void AddTotpManual_Click(object sender, RoutedEventArgs e)
    {
        TotpEntry? entry = Dialogs.AddTotpManual(this);
        if (entry is not null) SaveTotpEntry(entry);
    }

    private void AddTotp_Click(object sender, RoutedEventArgs e)
    {
        string? uri = Dialogs.Prompt(this, "Add TOTP account", "Paste the complete otpauth://totp URI. It is processed locally and encrypted immediately.");
        if (uri is not null) AddTotpUri(uri);
    }

    private void PasteTotp_Click(object sender, RoutedEventArgs e)
    {
        if (!Clipboard.ContainsText()) { MessageBox.Show(this, "The clipboard does not contain text."); return; }
        AddTotpUri(Clipboard.GetText());
    }

    private void ImportQr_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a QR-code image", Filter = "Images (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            if (new FileInfo(dialog.FileName).Length > 20 * 1024 * 1024) throw new System.FormatException("The QR image exceeds the 20 MiB safety limit.");
            using var imageStream = new FileStream(dialog.FileName, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            BitmapDecoder decoder = BitmapDecoder.Create(imageStream, BitmapCreateOptions.PreservePixelFormat | BitmapCreateOptions.IgnoreColorProfile, BitmapCacheOption.None);
            if (decoder.Frames.Count != 1) throw new System.FormatException("Animated or multi-frame QR images are not accepted.");
            BitmapSource source = decoder.Frames[0];
            ValidateImageDimensions(source.PixelWidth, source.PixelHeight);
            var converted = new FormatConvertedBitmap(source, PixelFormats.Bgra32, null, 0);
            int stride = checked(converted.PixelWidth * 4);
            byte[] pixels = new byte[checked(stride * converted.PixelHeight)];
            converted.CopyPixels(pixels, stride, 0);
            var luminance = new RGBLuminanceSource(pixels, converted.PixelWidth, converted.PixelHeight, RGBLuminanceSource.BitmapFormat.BGRA32);
            var reader = new BarcodeReaderGeneric { AutoRotate = true, Options = new DecodingOptions { TryHarder = true } };
            Result? result = reader.Decode(luminance);
            CryptographicOperations.ZeroMemory(pixels);
            if (result is null) throw new System.FormatException("No readable QR code was found in that image.");
            AddTotpUri(result.Text);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "QR import failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private async void ScanScreenQr_Click(object sender, RoutedEventArgs e)
    {
        WindowState previous = WindowState;
        try
        {
            WindowState = WindowState.Minimized;
            await Task.Delay(450);
            string? uri = await Task.Run(CaptureOtpAuthFromScreens);
            if (uri is null) throw new System.FormatException("No TOTP QR code was found on the visible screens.");
            AddTotpUri(uri);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Screen QR scan", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally
        {
            WindowState = previous == WindowState.Minimized ? WindowState.Maximized : previous;
            Activate();
        }
    }

    private static string? CaptureOtpAuthFromScreens()
    {
        int left = GetSystemMetrics(76);
        int top = GetSystemMetrics(77);
        int width = GetSystemMetrics(78);
        int height = GetSystemMetrics(79);
        if (width <= 0 || height <= 0) return null;
        ValidateImageDimensions(width, height);
        using var bitmap = new Drawing.Bitmap(width, height, DrawingImaging.PixelFormat.Format32bppArgb);
        using (Drawing.Graphics graphics = Drawing.Graphics.FromImage(bitmap))
            graphics.CopyFromScreen(left, top, 0, 0, new Drawing.Size(width, height), Drawing.CopyPixelOperation.SourceCopy);
        Drawing.Rectangle area = new(0, 0, bitmap.Width, bitmap.Height);
        DrawingImaging.BitmapData data = bitmap.LockBits(area, DrawingImaging.ImageLockMode.ReadOnly, DrawingImaging.PixelFormat.Format32bppArgb);
        try
        {
            int length = Math.Abs(data.Stride) * data.Height;
            byte[] pixels = new byte[length];
            Marshal.Copy(data.Scan0, pixels, 0, length);
            try
            {
                var source = new RGBLuminanceSource(pixels, bitmap.Width, bitmap.Height, RGBLuminanceSource.BitmapFormat.BGRA32);
                var reader = new BarcodeReaderGeneric { AutoRotate = true, Options = new DecodingOptions { TryHarder = true, PossibleFormats = [BarcodeFormat.QR_CODE] } };
                Result? result = reader.Decode(source);
                if (result?.Text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase) == true) return result.Text;
            }
            finally { CryptographicOperations.ZeroMemory(pixels); }
        }
        finally { bitmap.UnlockBits(data); }
        return null;
    }

    private static void ValidateImageDimensions(int width, int height)
    {
        if (width is < 1 or > 16_384 || height is < 1 or > 16_384 || (long)width * height > 40_000_000)
            throw new System.FormatException("The image dimensions exceed the QR scanner safety limit.");
    }

    private void AddTotpUri(string uri)
    {
        if (_profile is null) return;
        try
        {
            TotpEntry entry = TotpService.ParseOtpAuthUri(uri);
            SaveTotpEntry(entry);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "TOTP import failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void SaveTotpEntry(TotpEntry entry)
    {
        if (_profile is null) return;
        _profile.Data.TotpEntries.Add(entry);
        _profile.Data.AuditLog.Add(new AuditEvent { Type = "TOTP", Message = $"Added TOTP account: {entry.DisplayName}." });
        _repository.Save(_profile);
        RenderTotp();
    }

    private void CopyTotp(TotpEntry entry)
    {
        string value = TotpService.GetCode(entry).Code;
        Clipboard.SetText(value);
        MarkClipboardSensitive();
        _lastCopiedTotp = value;
        _ = ClearClipboardLater(value);
    }

    private async Task ClearClipboardLater(string expected)
    {
        await Task.Delay(TimeSpan.FromSeconds(15));
        await Dispatcher.InvokeAsync(() => ClearSensitiveClipboard(expected));
    }

    private void ClearSensitiveClipboard(string? expected = null)
    {
        string? tracked = expected ?? _lastCopiedTotp;
        if (tracked is null) return;
        try { if (Clipboard.ContainsText() && Clipboard.GetText() == tracked) Clipboard.Clear(); } catch { }
        if (_lastCopiedTotp == tracked) _lastCopiedTotp = null;
    }

    private static void MarkClipboardSensitive()
    {
        IntPtr memory = IntPtr.Zero;
        try
        {
            uint format = RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing");
            if (format == 0 || !OpenClipboard(IntPtr.Zero)) return;
            try
            {
                memory = GlobalAlloc(2, (nuint)sizeof(int));
                if (memory == IntPtr.Zero) return;
                IntPtr pointer = GlobalLock(memory);
                if (pointer == IntPtr.Zero) return;
                Marshal.WriteInt32(pointer, 0);
                GlobalUnlock(memory);
                if (SetClipboardData(format, memory) != IntPtr.Zero) memory = IntPtr.Zero;
            }
            finally { CloseClipboard(); }
        }
        catch { }
        finally { if (memory != IntPtr.Zero) GlobalFree(memory); }
    }

    private void DeleteTotp(TotpEntry entry)
    {
        if (_profile is null || !Dialogs.Confirm(this, "Delete TOTP account", $"Permanently delete {entry.DisplayName}?")) return;
        _profile.Data.TotpEntries.Remove(entry);
        _profile.Data.AuditLog.Add(new AuditEvent { Type = "TOTP", Message = $"Deleted TOTP account: {entry.DisplayName}." });
        _repository.Save(_profile); RenderTotp();
    }

    private void RenderTpm()
    {
        if (_profile is null) return;
        _pageVersion++;
        TpmStatus status = _tpm.Detect();
        if (status.Mode == TpmMode.Tpm12 && !_tpm12Acknowledged)
        {
            MessageBox.Show(this,
                "TPM 1.2 is legacy hardware. This section is limited to RSA-2048/SHA-1 and cannot provide modern ECC or attestation. You may continue in reduced-security mode, or avoid TPM key generation and use FIDO2 plus the encrypted vault. Consider enabling fTPM/PTT in firmware or upgrading to TPM 2.0.",
                "TPM 1.2 reduced-security mode", MessageBoxButton.OK, MessageBoxImage.Warning);
            _tpm12Acknowledged = true;
        }
        SetPage("Advanced TPM keys", "Optional hardware-bound keys — separate from FIDO2 passkeys");
        ContentPanel.Children.Clear(); _totpViews.Clear();
        ContentPanel.Children.Add(Banner(status.Mode == TpmMode.None ? "TPM unavailable" : status.Mode == TpmMode.Tpm12 ? "Legacy TPM 1.2" : "TPM 2.0 ready", status.Detail, status.Mode == TpmMode.None ? "danger" : status.Mode == TpmMode.Tpm12 ? "warning" : "success"));
        ContentPanel.Children.Add(InfoCard("Hardware status", $"Version {status.Version} · Manufacturer {status.Manufacturer}", $"Present {status.Present} · Enabled {status.Enabled} · Owned {status.Owned}"));
        var actions = new WrapPanel { Margin = new Thickness(0, 14, 0, 20) };
        var ecc = ActionButton("Generate ECC P-256 key", (_, _) => GenerateTpmKey(true), true); ecc.IsEnabled = status.Mode == TpmMode.Tpm20;
        var rsa = ActionButton("Generate RSA-2048 key", (_, _) => GenerateTpmKey(false)); rsa.IsEnabled = status.Mode != TpmMode.None;
        actions.Children.Add(ecc);
        actions.Children.Add(rsa);
        actions.Children.Add(ActionButton("Refresh TPM status", (_, _) => { _tpm.RefreshStatus(); RenderTpm(); }));
        ContentPanel.Children.Add(actions);
        ContentPanel.Children.Add(SectionTitle("Profile TPM keys", "Only public blobs and provider handles are stored in the vault"));
        if (_profile.Data.TpmKeys.Count == 0) ContentPanel.Children.Add(EmptyCard("No TPM keys", "Create a hardware-bound signing or encryption key when TPM support is available."));
        foreach (TpmKeyRecord key in _profile.Data.TpmKeys.ToArray())
        {
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock { Text = key.Name, FontSize = 18, FontWeight = FontWeights.SemiBold });
            panel.Children.Add(new TextBlock { Text = key.Algorithm + " · " + key.CreatedUtc.LocalDateTime.ToString("g"), Foreground = Muted(), Margin = new Thickness(0, 5, 0, 4) });
            panel.Children.Add(new TextBlock { Text = key.AttestationStatus, Foreground = Muted(), FontSize = 12 });
            panel.Children.Add(ActionButton("Delete TPM key", (_, _) => DeleteTpmKey(key)));
            ContentPanel.Children.Add(Card(panel));
        }
    }

    private void GenerateTpmKey(bool ecc)
    {
        if (_profile is null) return;
        TpmStatus status = _tpm.Detect();
        string? name = Dialogs.Prompt(this, "Generate TPM key", "Local display name", ecc ? "Signing key" : "Encryption key");
        if (string.IsNullOrWhiteSpace(name)) return;
        try
        {
            TpmKeyRecord key = _tpm.GenerateKey(name.Trim(), ecc, status.Mode);
            _profile.Data.TpmKeys.Add(key);
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "TPM", Message = $"Generated non-exportable {key.Algorithm} key: {key.Name}." });
            _repository.Save(_profile); RenderTpm();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "TPM key generation failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void DeleteTpmKey(TpmKeyRecord key)
    {
        if (_profile is null || !Dialogs.Confirm(this, "Delete TPM key", "This is irreversible. The private key cannot be recovered or exported.")) return;
        try
        {
            _tpm.DeleteKey(key.ProviderKeyName);
            _profile.Data.TpmKeys.Remove(key);
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "TPM", Message = $"Deleted TPM key: {key.Name}." });
            _repository.Save(_profile); RenderTpm();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "TPM key deletion failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void RenderSettings()
    {
        if (_profile is null) return;
        _pageVersion++;
        SetPage("Settings & audit", "Profile-specific security, appearance, backup, and accountability");
        ContentPanel.Children.Clear(); _totpViews.Clear();
        ContentPanel.Children.Add(SectionTitle("Appearance", "Theme is encrypted with this profile's settings"));
        var themes = new WrapPanel();
        foreach (AppTheme theme in Enum.GetValues<AppTheme>()) themes.Children.Add(ActionButton(theme.ToString(), (_, _) => SetTheme(theme), _profile.Data.Settings.Theme == theme));
        ContentPanel.Children.Add(themes);
        ContentPanel.Children.Add(SectionTitle("Auto-lock", "Idle activity is checked locally once per second"));
        var timeout = new ComboBox { Width = 220, HorizontalAlignment = HorizontalAlignment.Left, ItemsSource = new[] { 1, 5, 15, 30, 60 }, SelectedItem = _profile.Data.Settings.AutoLockMinutes, Margin = new Thickness(0, 0, 0, 22) };
        timeout.SelectionChanged += (_, _) => { if (_profile is not null && timeout.SelectedItem is int minutes) { _profile.Data.Settings.AutoLockMinutes = minutes; _repository.Save(_profile); } };
        ContentPanel.Children.Add(timeout);

        ContentPanel.Children.Add(SectionTitle("Profile security", "Sensitive changes require re-authentication"));
        var security = new WrapPanel { Margin = new Thickness(0, 0, 0, 20) };
        security.Children.Add(ActionButton("Change PIN", ChangePin_Click));
        security.Children.Add(ActionButton(_profile.Metadata.KeyfileRequired ? "Regenerate keyfile" : "Enable keyfile", ConfigureKeyfile_Click));
        if (_profile.Metadata.KeyfileRequired) security.Children.Add(ActionButton("Disable keyfile", DisableKeyfile_Click));
        security.Children.Add(ActionButton("Rename profile", RenameProfile_Click));
        security.Children.Add(ActionButton("Delete profile", DeleteProfile_Click));
        ContentPanel.Children.Add(security);

        ContentPanel.Children.Add(SectionTitle("Backup & restore", "Password-protected AES-GCM backup with integrity verification"));
        var backup = new WrapPanel { Margin = new Thickness(0, 0, 0, 20) };
        backup.Children.Add(ActionButton("Export encrypted backup", ExportBackup_Click));
        backup.Children.Add(ActionButton("Restore encrypted backup", RestoreBackup_Click));
        ContentPanel.Children.Add(backup);

        ContentPanel.Children.Add(SectionTitle("Audit log", $"{_profile.Data.AuditLog.Count} encrypted local events"));
        var auditActions = new WrapPanel();
        auditActions.Children.Add(ActionButton("Export signed CSV", ExportAudit_Click, true));
        auditActions.Children.Add(ActionButton("Clear log", ClearAudit_Click));
        ContentPanel.Children.Add(auditActions);
        foreach (AuditEvent item in _profile.Data.AuditLog.OrderByDescending(x => x.TimestampUtc).Take(60))
            ContentPanel.Children.Add(InfoCard(item.Type + " · " + item.Outcome, item.TimestampUtc.LocalDateTime.ToString("g"), item.Message));

        TpmStatus tpm = _tpm.Detect();
        ContentPanel.Children.Add(SectionTitle("About", "Darks FIDO2 0.4.4"));
        ContentPanel.Children.Add(InfoCard("Security mode", _profile.Metadata.DeviceProtection + " vault wrapping", tpm.Detail));
        ContentPanel.Children.Add(Banner("Scope", "Darks FIDO2 hardens and encrypts its own data. It is not a replacement for antivirus or EDR software. No telemetry or secret-bearing network calls are implemented.", "success"));
        ContentPanel.Children.Add(new TextBlock { Text = "CLI: darksfido-cli list-keys | vault-status | check-backups | export-audit --signed --output <path>", Foreground = Muted(), FontFamily = new FontFamily("Cascadia Mono"), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 12) });
    }

    private void SetTheme(AppTheme theme)
    {
        if (_profile is null) return;
        _profile.Data.Settings.Theme = theme; ThemeManager.Apply(theme); AuroraBackground.Opacity = theme == AppTheme.Aurora ? 1 : 0; _repository.Save(_profile); RenderSettings();
    }

    private void ChangePin_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return;
        string? current = Dialogs.Prompt(this, "Verify current PIN", "Enter the current PIN/passphrase.", secret: true);
        if (current is null) return;
        byte[]? keyfile = ReadCurrentKeyfile();
        if (_profile.Metadata.KeyfileRequired && keyfile is null) return;
        try
        {
            using (UnlockedProfile verified = _repository.Unlock(_profile.Metadata.Id, current, keyfile)) { }
            string? next = Dialogs.Prompt(this, "New PIN", "Enter a new PIN/passphrase (minimum 10 characters).", secret: true);
            if (next is null) return;
            string? confirm = Dialogs.Prompt(this, "Confirm new PIN", "Enter it again.", secret: true);
            if (next != confirm) throw new InvalidOperationException("The new PIN/passphrase values do not match.");
            string? recovery = _profile.Metadata.KeyfileRequired ? VaultCryptography.GenerateRecoveryCode() : null;
            _repository.ChangePin(_profile, next, keyfile, recovery);
            if (recovery is not null) MessageBox.Show(this, "Your old recovery code is invalid. Store this replacement separately:\n\n" + recovery, "New recovery code", MessageBoxButton.OK, MessageBoxImage.Warning);
            MessageBox.Show(this, "PIN/passphrase changed.");
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "PIN change failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { if (keyfile is not null) CryptographicOperations.ZeroMemory(keyfile); }
    }

    private void ConfigureKeyfile_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return;
        string? pin = Dialogs.Prompt(this, "Verify PIN", "Enter the current PIN/passphrase.", secret: true); if (pin is null) return;
        byte[]? current = ReadCurrentKeyfile(); if (_profile.Metadata.KeyfileRequired && current is null) return;
        var save = new SaveFileDialog { Title = "Choose a new master keyfile location", Filter = "Darks FIDO2 keyfile (*.dfkey)|*.dfkey", AddExtension = true };
        if (save.ShowDialog(this) != true) { if (current is not null) CryptographicOperations.ZeroMemory(current); return; }
        byte[] next = VaultCryptography.GenerateKeyfile();
        string recovery = VaultCryptography.GenerateRecoveryCode();
        try
        {
            _repository.ConfigureKeyfile(_profile, pin, current, next, recovery);
            SecureFile.AtomicWrite(save.FileName, next);
            _keyfilePath = save.FileName;
            MessageBox.Show(this, "The previous keyfile is now invalid. Store this replacement recovery code separately:\n\n" + recovery, "Keyfile updated", MessageBoxButton.OK, MessageBoxImage.Warning);
            RenderSettings();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Keyfile update failed", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { CryptographicOperations.ZeroMemory(next); if (current is not null) CryptographicOperations.ZeroMemory(current); }
    }

    private void DisableKeyfile_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null || !Dialogs.Confirm(this, "Disable keyfile", "This lowers the profile from PIN + possession to PIN-only unlock. Continue?")) return;
        string? pin = Dialogs.Prompt(this, "Verify PIN", "Enter the current PIN/passphrase.", secret: true); if (pin is null) return;
        byte[]? current = ReadCurrentKeyfile(); if (current is null) return;
        try { _repository.ConfigureKeyfile(_profile, pin, current, null, null); _keyfilePath = null; RenderSettings(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Keyfile change failed", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { CryptographicOperations.ZeroMemory(current); }
    }

    private byte[]? ReadCurrentKeyfile()
    {
        if (_profile?.Metadata.KeyfileRequired != true) return null;
        if (string.IsNullOrWhiteSpace(_keyfilePath) || !File.Exists(_keyfilePath))
        {
            var open = new OpenFileDialog { Title = "Select the current master keyfile", Filter = "Darks FIDO2 keyfile (*.dfkey)|*.dfkey|All files (*.*)|*.*" };
            if (open.ShowDialog(this) != true) return null;
            _keyfilePath = open.FileName;
        }
        return SecureFile.ReadAllBytes(_keyfilePath, 1024 * 1024);
    }

    private void RenameProfile_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return; string? name = Dialogs.Prompt(this, "Rename profile", "New profile name", _profile.Data.ProfileName);
        if (string.IsNullOrWhiteSpace(name)) return;
        try { _repository.Rename(_profile, name); SideProfileName.Text = name; RenderSettings(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message); }
    }

    private void DeleteProfile_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return;
        string? pin = Dialogs.Prompt(this, "Verify PIN", "Enter the profile PIN/passphrase before deletion.", secret: true); if (pin is null) return;
        byte[]? keyfile = ReadCurrentKeyfile(); if (_profile.Metadata.KeyfileRequired && keyfile is null) return;
        try
        {
            using (UnlockedProfile verified = _repository.Unlock(_profile.Metadata.Id, pin, keyfile)) { }
            string? typed = Dialogs.Prompt(this, "Irreversible deletion", "Type the exact profile name to permanently delete its encrypted vault:\n\n" + _profile.Data.ProfileName);
            if (typed is null) return;
            _passkeyContext.Clear(_profile.Metadata.Id);
            _repository.Delete(_profile, typed); _profile = null; Shell.Visibility = Visibility.Collapsed; GateLayer.Visibility = Visibility.Visible; LoadProfiles();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Profile not deleted", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { if (keyfile is not null) CryptographicOperations.ZeroMemory(keyfile); }
    }

    private void ExportBackup_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return; var save = new SaveFileDialog { Filter = "Darks FIDO2 encrypted backup (*.dfbackup)|*.dfbackup", AddExtension = true };
        if (save.ShowDialog(this) != true) return; string? password = Dialogs.Prompt(this, "Backup password", "Use a separate password of at least 10 characters.", secret: true); if (password is null) return;
        string? confirm = Dialogs.Prompt(this, "Confirm backup password", "Enter the backup password again.", secret: true); if (password != confirm) { MessageBox.Show(this, "Passwords do not match."); return; }
        try { new VaultBackupService().Export(_profile.Data, password, save.FileName); _profile.Data.AuditLog.Add(new AuditEvent { Type = "Backup", Message = "Encrypted vault backup exported." }); _repository.Save(_profile); MessageBox.Show(this, "Encrypted backup written successfully."); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Backup failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void RestoreBackup_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return; var open = new OpenFileDialog { Filter = "Darks FIDO2 encrypted backup (*.dfbackup)|*.dfbackup" };
        if (open.ShowDialog(this) != true) return; string? password = Dialogs.Prompt(this, "Backup password", "Enter the backup password.", secret: true); if (password is null) return;
        if (!Dialogs.Confirm(this, "Restore backup", "Replace this profile's keys metadata, TOTP accounts, settings, and audit history with the backup?")) return;
        try
        {
            VaultData restored = new VaultBackupService().Import(open.FileName, password);
            _profile.Data.FidoKeys = restored.FidoKeys; _profile.Data.TotpEntries = restored.TotpEntries; _profile.Data.TpmKeys = restored.TpmKeys;
            _profile.Data.Settings = restored.Settings; _profile.Data.AuditLog = restored.AuditLog;
            _profile.Data.AuditSigningPrivateKeyPkcs8 = restored.AuditSigningPrivateKeyPkcs8; _profile.Data.AuditSigningPublicKeySpki = restored.AuditSigningPublicKeySpki;
            _profile.Data.AuditLog.Add(new AuditEvent { Type = "Backup", Message = "Encrypted backup restored after integrity verification." });
            _repository.Save(_profile); RenderSettings();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Restore failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void ExportAudit_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null) return; var save = new SaveFileDialog { Filter = "CSV report (*.csv)|*.csv", AddExtension = true };
        if (save.ShowDialog(this) != true) return;
        try { SignedAuditExport result = new AuditExportService().ExportSignedCsv(_profile.Data, save.FileName); _repository.Save(_profile); MessageBox.Show(this, "Signed report written with sidecar signature and public key:\n\n" + result.CsvPath); RenderSettings(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Audit export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void ClearAudit_Click(object sender, RoutedEventArgs e)
    {
        if (_profile is null || !Dialogs.Confirm(this, "Clear audit log", "Permanently clear all audit events for this profile?")) return;
        _profile.Data.AuditLog.Clear(); _profile.Data.AuditLog.Add(new AuditEvent { Type = "Audit", Message = "Audit log cleared by user." }); _repository.Save(_profile); RenderSettings();
    }

    private void Clock_Tick(object? sender, EventArgs e)
    {
        if (_unlockInProgress) return;
        foreach ((TextBlock code, TextBlock countdown, ProgressBar progress, TotpEntry entry) in _totpViews.ToArray())
        {
            TotpCode current = TotpService.GetCode(entry); code.Text = FormatCode(current.Code); countdown.Text = $"Refreshes in {current.SecondsRemaining}s · {entry.Period}s · {entry.Algorithm}"; progress.Value = current.Progress;
        }
        if (_profile is not null)
        {
            if (DateTimeOffset.UtcNow - _lastProfileContextRefreshUtc >= TimeSpan.FromSeconds(30))
            {
                _passkeyContext.SetActiveProfile(_profile.Metadata.Id);
                _lastProfileContextRefreshUtc = DateTimeOffset.UtcNow;
            }
            SyncProviderCredentials();
            if (DateTimeOffset.UtcNow - _lastActivity >= TimeSpan.FromMinutes(Math.Max(1, _profile.Data.Settings.AutoLockMinutes))) LockVault();
        }
    }

    private void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        _lastActivity = DateTimeOffset.UtcNow;
        if (e.Key == Key.L && Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) { LockVault(minimize: true); e.Handled = true; }
    }

    private void MainWindow_SourceInitialized(object? sender, EventArgs e)
    {
        IntPtr handle = new WindowInteropHelper(this).Handle;
        HwndSource.FromHwnd(handle)?.AddHook(WndProc);
        RegisterHotKey(handle, HotkeyId, 0x0002 | 0x4000, 0x4C);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == 0x0312 && wParam.ToInt32() == HotkeyId) { Dispatcher.Invoke(() => LockVault(minimize: true)); handled = true; }
        return IntPtr.Zero;
    }

    private async void MainWindow_Closed(object? sender, EventArgs e)
    {
        ClearSensitiveClipboard();
        if (_profile is not null) _passkeyContext.Clear(_profile.Metadata.Id);
        _profile?.Dispose(); _profile = null;
        UnregisterHotKey(new WindowInteropHelper(this).Handle, HotkeyId);
        if (_cliServer is not null) await _cliServer.DisposeAsync();
    }

    private void SyncProviderCredentials(bool force = false)
    {
        if (_profile is null) return;
        try
        {
            DateTime writeUtc = File.Exists(_providerStore.StorePath) ? File.GetLastWriteTimeUtc(_providerStore.StorePath) : DateTime.MinValue;
            if (!force && writeUtc <= _lastProviderStoreWriteUtc) return;

            IReadOnlyList<SoftwarePasskeyCredential> credentials = _providerStore.ClaimUnassigned(_profile.Metadata.Id);
            bool changed = false;
            foreach (SoftwarePasskeyCredential credential in credentials)
            {
                string credentialId = Convert.ToBase64String(credential.CredentialId);
                FidoKeyRecord? existing = _profile.Data.FidoKeys.FirstOrDefault(k => string.Equals(k.CredentialId, credentialId, StringComparison.Ordinal));
                if (existing is not null)
                {
                    bool becameConfirmed = existing.RegistrationStatus == PasskeyRegistrationStatus.Pending &&
                                           credential.RegistrationStatus == PasskeyRegistrationStatus.Confirmed;
                    bool recordChanged = existing.RegistrationStatus != credential.RegistrationStatus ||
                                         existing.ConfirmedUtc != credential.ConfirmedUtc ||
                                         existing.LastUsedUtc != credential.LastUsedUtc ||
                                         existing.SignCounter != credential.SignCount ||
                                         !string.Equals(existing.RpId, credential.RpId, StringComparison.Ordinal) ||
                                         !string.Equals(existing.UserName, credential.UserName, StringComparison.Ordinal);
                    existing.RegistrationStatus = credential.RegistrationStatus;
                    existing.ConfirmedUtc = credential.ConfirmedUtc;
                    existing.LastUsedUtc = credential.LastUsedUtc;
                    existing.SignCounter = credential.SignCount;
                    existing.RpId = credential.RpId;
                    existing.UserName = credential.UserName;
                    if (becameConfirmed)
                        _profile.Data.AuditLog.Add(new AuditEvent { Type = "FIDO2", Message = $"Confirmed site registration for {existing.Name} after successful authentication." });
                    changed |= recordChanged;
                    continue;
                }
                string name = string.IsNullOrWhiteSpace(credential.RpName) ? credential.RpId : credential.RpName;
                if (!string.IsNullOrWhiteSpace(credential.UserName)) name += " · " + credential.UserName;
                _profile.Data.FidoKeys.Add(new FidoKeyRecord
                {
                    Name = name,
                    AuthenticatorId = "DarksFIDO2.Provider",
                    CredentialId = credentialId,
                    Type = "Darks FIDO2 virtual passkey",
                    Transport = credential.HardwareBacked ? "Internal / TPM-backed" : "Internal / non-exportable Windows key",
                    Aaguid = VirtualProviderAaguid,
                    RpId = credential.RpId,
                    UserName = credential.UserName,
                    RegistrationStatus = credential.RegistrationStatus,
                    ResidentKey = true,
                    SignCounter = credential.SignCount,
                    AddedUtc = credential.CreatedUtc,
                    ConfirmedUtc = credential.ConfirmedUtc,
                    LastUsedUtc = credential.LastUsedUtc
                });
                _profile.Data.AuditLog.Add(new AuditEvent
                {
                    Type = "FIDO2",
                    Message = credential.RegistrationStatus == PasskeyRegistrationStatus.Pending
                        ? $"Created pending virtual passkey for {credential.RpId} in profile {_profile.Data.ProfileName}; awaiting site confirmation."
                        : $"Saved confirmed virtual passkey for {credential.RpId} to profile {_profile.Data.ProfileName}."
                });
                changed = true;
            }
            if (changed) _repository.Save(_profile);
            _lastProviderStoreWriteUtc = File.Exists(_providerStore.StorePath) ? File.GetLastWriteTimeUtc(_providerStore.StorePath) : writeUtc;
            _providerSyncError = null;
        }
        catch (Exception ex) { _providerSyncError = ex.Message; }
    }

    private async Task WarnIfUnsignedAsync()
    {
        if (_integrityWarningShown || await Task.Run(HasTrustedSignature)) return;
        _integrityWarningShown = true;
        MessageBox.Show(this, "Self-integrity check: this executable does not have a signature trusted by the current Windows account. This is expected only for a development build. Do not distribute it as a production security tool.", "Signature warning", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private bool HasTrustedSignature()
    {
        if (_trustedSignature is bool cached) return cached;
        try
        {
            return (_trustedSignature = AuthenticodeVerifier.IsTrusted(Environment.ProcessPath!)).Value;
        }
        catch { return (_trustedSignature = false).Value; }
    }

    private void ProtectWindowFromCapture(bool protect)
    {
        try { SetWindowDisplayAffinity(new WindowInteropHelper(this).Handle, protect ? 0x11u : 0u); } catch { }
    }

    private void GitHub_Click(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(GitHubUrl) { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Unable to open GitHub", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void SetPage(string title, string subtitle)
    {
        PageTitle.Text = title;
        PageSubtitle.Text = subtitle;
        Button[] navigation = [FidoNav, DashboardNav, TotpNav, TpmNav, SettingsNav];
        foreach (Button button in navigation)
        {
            button.Background = Brushes.Transparent;
            button.BorderBrush = Brushes.Transparent;
        }
        Button selected = title.StartsWith("Passkeys", StringComparison.Ordinal) ? FidoNav :
            title.StartsWith("Dashboard", StringComparison.Ordinal) ? DashboardNav :
            title.StartsWith("2FA", StringComparison.Ordinal) ? TotpNav :
            title.StartsWith("TPM", StringComparison.Ordinal) ? TpmNav :
            SettingsNav;
        selected.Background = (Brush)FindResource("AccentSurfaceBrush");
        selected.BorderBrush = (Brush)FindResource("AccentBrush");
    }
    private Brush Muted() => (Brush)FindResource("MutedBrush");
    private static string FormatCode(string code) => code.Length == 6 ? code[..3] + " " + code[3..] : code.Length == 8 ? code[..4] + " " + code[4..] : code;

    private Button ActionButton(string text, RoutedEventHandler handler, bool accent = false)
    {
        var button = new Button { Content = text };
        if (accent) button.Style = (Style)FindResource("PrimaryButton");
        button.Click += handler; return button;
    }

    private Border Card(UIElement child) => new()
    {
        Child = child,
        Background = (Brush)FindResource("PanelBrush"),
        BorderBrush = (Brush)FindResource("BorderBrush"),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(16),
        Padding = new Thickness(22),
        Margin = new Thickness(0, 0, 0, 13)
    };

    private Border StatCard(string value, string label)
    {
        var panel = new StackPanel();
        panel.Children.Add(new Border { Width = 28, Height = 3, CornerRadius = new CornerRadius(99), Background = (Brush)FindResource("AccentBrush"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 13) });
        panel.Children.Add(new TextBlock { Text = value, FontFamily = new FontFamily("Segoe UI Variable Display"), FontSize = 31, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = label, Foreground = Muted(), Margin = new Thickness(0, 6, 0, 0), TextWrapping = TextWrapping.Wrap });
        var card = Card(panel); card.Margin = new Thickness(0, 0, 12, 0); return card;
    }

    private UIElement SectionTitle(string title, string subtitle)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 18, 0, 13) };
        panel.Children.Add(new TextBlock { Text = title, FontFamily = new FontFamily("Segoe UI Variable Display"), FontSize = 20, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = subtitle, Foreground = Muted(), Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap, LineHeight = 20 });
        return panel;
    }

    private Border InfoCard(string title, string subtitle, string detail)
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = title, FontSize = 17, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        if (!string.IsNullOrWhiteSpace(subtitle))
            panel.Children.Add(new TextBlock { Text = subtitle, Foreground = Muted(), Margin = new Thickness(0, 5, 0, 4), TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(new TextBlock { Text = detail, Foreground = (Brush)FindResource("SubtleTextBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap, LineHeight = 18 });
        return Card(panel);
    }

    private Border EmptyCard(string title, string detail) => InfoCard("◇  " + title, "", detail);

    private Border Banner(string title, string detail, string kind)
    {
        string colorKey = kind == "danger" ? "DangerBrush" : kind == "warning" ? "WarningBrush" : "SuccessBrush";
        string surfaceKey = kind == "danger" ? "DangerSurfaceBrush" : kind == "warning" ? "WarningSurfaceBrush" : "SuccessSurfaceBrush";
        Brush color = (Brush)FindResource(colorKey);
        var panel = new Grid();
        panel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        panel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(16) });
        panel.ColumnDefinitions.Add(new ColumnDefinition());
        panel.Children.Add(new Border { Background = color, CornerRadius = new CornerRadius(99) });
        var copy = new StackPanel();
        copy.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, Foreground = color, FontSize = 15, TextWrapping = TextWrapping.Wrap });
        copy.Children.Add(new TextBlock { Text = detail, TextWrapping = TextWrapping.Wrap, LineHeight = 20, Margin = new Thickness(0, 5, 0, 0) });
        Grid.SetColumn(copy, 2);
        panel.Children.Add(copy);
        var card = Card(panel);
        card.Background = (Brush)FindResource(surfaceKey);
        card.BorderBrush = (Brush)FindResource("BorderBrush");
        card.Padding = new Thickness(16);
        card.Margin = new Thickness(0, 0, 0, 15);
        return card;
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint virtualKey);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    [DllImport("user32.dll")] private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint affinity);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterClipboardFormat(string format);
    [DllImport("user32.dll")] private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern IntPtr SetClipboardData(uint format, IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GlobalAlloc(uint flags, nuint bytes);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GlobalLock(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr memory);
}

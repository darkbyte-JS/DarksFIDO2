using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows.Threading;
using DarksFIDO2.Core;
using DarksFIDO2.Core.Interop;
using DarksFIDO2.Core.Passkeys;
using DarksFIDO2.Core.Storage;

namespace DarksFIDO2.App.Services;

public interface IVaultSession : IDisposable
{
    ProfileIndex ProfileIndex { get; }
    UnlockedProfile? CurrentProfile { get; }
    bool IsUnlocked { get; }
    int AutoLockRemainingSeconds { get; }
    AppPaths Paths { get; }
    VaultRepository Repository { get; }
    TpmService Tpm { get; }
    WebAuthnService WebAuthn { get; }
    SoftwarePasskeyStore SoftwarePasskeys { get; }
    VaultBackupService Backup { get; }
    AuditExportService AuditExport { get; }

    event Action? SessionChanged;
    event Action? AutoLockTick;

    void ReloadProfiles();
    void Unlock(Guid profileId, string pin, byte[]? keyfile);
    void UnlockWithRecovery(Guid profileId, string pin, string recoveryCode);
    void CreateProfile(ProfileCreationRequest request);
    void Lock();
    void Save();
    void AddAuditEvent(string type, string outcome, string message);
    bool VerifyCurrentPin(string pin);
}

public sealed class VaultSession : IVaultSession
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    private readonly DispatcherTimer _clock;
    private readonly PasskeyProviderContext _passkeyContext;
    private CliBridgeServer? _cliServer;
    private int _remainingSeconds = 300;
    private byte[]? _currentKeyfile;

    public VaultSession()
    {
        Paths = new AppPaths();
        Tpm = new TpmService();
        Repository = new VaultRepository(Paths, Tpm);
        WebAuthn = new WebAuthnService();
        SoftwarePasskeys = new SoftwarePasskeyStore();
        Backup = new VaultBackupService();
        AuditExport = new AuditExportService();
        _passkeyContext = new PasskeyProviderContext();

        ProfileIndex = Repository.LoadIndex();

        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += OnClockTick;
        _clock.Start();
    }

    public AppPaths Paths { get; }
    public VaultRepository Repository { get; }
    public TpmService Tpm { get; }
    public WebAuthnService WebAuthn { get; }
    public SoftwarePasskeyStore SoftwarePasskeys { get; }
    public VaultBackupService Backup { get; }
    public AuditExportService AuditExport { get; }

    public ProfileIndex ProfileIndex { get; private set; }
    public UnlockedProfile? CurrentProfile { get; private set; }
    public bool IsUnlocked => CurrentProfile is not null;
    public int AutoLockRemainingSeconds => _remainingSeconds;

    public event Action? SessionChanged;
    public event Action? AutoLockTick;

    public void ReloadProfiles()
    {
        ProfileIndex = Repository.LoadIndex();
        SessionChanged?.Invoke();
    }

    public void Unlock(Guid profileId, string pin, byte[]? keyfile)
    {
        Lock();

        UnlockedProfile unlocked = Repository.Unlock(profileId, pin, keyfile);
        CurrentProfile = unlocked;
        _currentKeyfile = keyfile is not null ? (byte[])keyfile.Clone() : null;
        _remainingSeconds = unlocked.Data.Settings.AutoLockMinutes * 60;

        // Passkey provider heartbeat
        _passkeyContext.SetActiveProfile(unlocked.Metadata.Id);

        // Start CLI bridge server
        try
        {
            _cliServer = new CliBridgeServer(() => CurrentProfile);
            _cliServer.Start();
        }
        catch { }

        AddAuditEvent("Vault", "Success", $"Profile '{unlocked.Metadata.Name}' unlocked.");
        SessionChanged?.Invoke();
    }

    public void UnlockWithRecovery(Guid profileId, string pin, string recoveryCode)
    {
        Lock();

        UnlockedProfile unlocked = Repository.UnlockWithRecovery(profileId, pin, recoveryCode);
        CurrentProfile = unlocked;
        _currentKeyfile = null;
        _remainingSeconds = unlocked.Data.Settings.AutoLockMinutes * 60;

        _passkeyContext.SetActiveProfile(unlocked.Metadata.Id);

        try
        {
            _cliServer = new CliBridgeServer(() => CurrentProfile);
            _cliServer.Start();
        }
        catch { }

        AddAuditEvent("Vault", "Success", $"Profile '{unlocked.Metadata.Name}' unlocked via emergency recovery.");
        SessionChanged?.Invoke();
    }

    public void CreateProfile(ProfileCreationRequest request)
    {
        Lock();
        UnlockedProfile created = Repository.CreateProfile(request);
        ReloadProfiles();
        CurrentProfile = created;
        _currentKeyfile = request.KeyfileBytes is not null ? (byte[])request.KeyfileBytes.Clone() : null;
        _remainingSeconds = created.Data.Settings.AutoLockMinutes * 60;

        _passkeyContext.SetActiveProfile(created.Metadata.Id);

        try
        {
            _cliServer = new CliBridgeServer(() => CurrentProfile);
            _cliServer.Start();
        }
        catch { }

        AddAuditEvent("Vault", "Success", $"New profile '{created.Metadata.Name}' initialized.");
        SessionChanged?.Invoke();
    }

    public void Lock()
    {
        if (CurrentProfile is not null)
        {
            Guid profileId = CurrentProfile.Metadata.Id;
            try
            {
                AddAuditEvent("Vault", "Success", "Profile locked.");
                Repository.Save(CurrentProfile);
            }
            catch { }

            // Clear provider heartbeat
            _passkeyContext.Clear(profileId);

            // Dispose profile (scrubs master key from memory)
            CurrentProfile.Dispose();
            CurrentProfile = null;
        }

        if (_currentKeyfile is not null)
        {
            CryptographicOperations.ZeroMemory(_currentKeyfile);
            _currentKeyfile = null;
        }

        if (_cliServer is not null)
        {
            try { _ = _cliServer.DisposeAsync(); } catch { }
            _cliServer = null;
        }

        SessionChanged?.Invoke();
    }

    public void Save()
    {
        if (CurrentProfile is null) return;
        Repository.Save(CurrentProfile);
    }

    public bool VerifyCurrentPin(string pin)
    {
        if (CurrentProfile is null || string.IsNullOrWhiteSpace(pin)) return false;
        try
        {
            using UnlockedProfile verified = Repository.Unlock(CurrentProfile.Metadata.Id, pin, _currentKeyfile);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void AddAuditEvent(string type, string outcome, string message)
    {
        if (CurrentProfile is null) return;
        CurrentProfile.Data.AuditLog.Add(new AuditEvent
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Type = type,
            Outcome = outcome,
            Message = message
        });
    }

    private void OnClockTick(object? sender, EventArgs e)
    {
        if (CurrentProfile is null) return;

        // Refresh provider heartbeat timestamp every 1s
        _passkeyContext.SetActiveProfile(CurrentProfile.Metadata.Id);

        // Idle time detection via GetLastInputInfo
        var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (GetLastInputInfo(ref lii))
        {
            uint idleTicks = unchecked((uint)Environment.TickCount - lii.dwTime);
            int idleSeconds = (int)(idleTicks / 1000);
            int timeoutSeconds = CurrentProfile.Data.Settings.AutoLockMinutes * 60;

            _remainingSeconds = Math.Max(0, timeoutSeconds - idleSeconds);
            AutoLockTick?.Invoke();

            if (idleSeconds >= timeoutSeconds)
            {
                Lock();
                return;
            }
        }
        else
        {
            _remainingSeconds = Math.Max(0, _remainingSeconds - 1);
            AutoLockTick?.Invoke();
            if (_remainingSeconds <= 0)
            {
                Lock();
                return;
            }
        }
    }

    public void Dispose()
    {
        _clock.Stop();
        Lock();
    }
}

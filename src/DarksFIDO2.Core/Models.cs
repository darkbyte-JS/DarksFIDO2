using System.Text.Json.Serialization;

namespace DarksFIDO2.Core;

public enum AppTheme { Dark, Light, Aurora }
public enum TpmMode { None, Tpm12, Tpm20 }
public enum DeviceProtection { Dpapi, Tpm }
public enum PasskeyRegistrationStatus { Confirmed, Pending }

public sealed record ProfileSummary(Guid Id, string Name, bool KeyfileRequired, DateTimeOffset CreatedUtc);

public sealed class ProfileIndex
{
    public List<ProfileSummary> Profiles { get; set; } = [];
    public Guid? LastProfileId { get; set; }
}

public sealed class ProfileMetadata
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "Profile";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public byte[] Salt { get; set; } = [];
    public int Pbkdf2Iterations { get; set; } = 600_000;
    public bool KeyfileRequired { get; set; }
    public byte[]? KeyfileHash { get; set; }
    public DeviceProtection DeviceProtection { get; set; }
    public byte[] ProtectedWrappedMasterKey { get; set; } = [];
    public string? TpmWrappingKeyName { get; set; }
    public byte[]? ProtectedRecoveryWrappedMasterKey { get; set; }
    public byte[]? RecoverySalt { get; set; }
}

public sealed class VaultData
{
    public int SchemaVersion { get; set; } = 1;
    public Guid ProfileId { get; set; }
    public string ProfileName { get; set; } = "Profile";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public AppSettings Settings { get; set; } = new();
    public List<FidoKeyRecord> FidoKeys { get; set; } = [];
    public List<TotpEntry> TotpEntries { get; set; } = [];
    public List<TpmKeyRecord> TpmKeys { get; set; } = [];
    public List<AuditEvent> AuditLog { get; set; } = [];
    public byte[]? AuditSigningPrivateKeyPkcs8 { get; set; }
    public byte[]? AuditSigningPublicKeySpki { get; set; }
}

public sealed class AppSettings
{
    public AppTheme Theme { get; set; } = AppTheme.Aurora;
    public int AutoLockMinutes { get; set; } = 5;
    public bool WindowsHelloEnabled { get; set; }
    public int HealthReminderDays { get; set; } = 60;
    public DateTimeOffset? LastHealthReminderUtc { get; set; }
}

public sealed class FidoKeyRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "Security key";
    public string AuthenticatorId { get; set; } = "";
    public string CredentialId { get; set; } = "";
    public string Type { get; set; } = "Roaming / external";
    public string Transport { get; set; } = "USB / NFC / BLE";
    public string Aaguid { get; set; } = "Unknown";
    public string RpId { get; set; } = "";
    public string UserName { get; set; } = "";
    public PasskeyRegistrationStatus RegistrationStatus { get; set; } = PasskeyRegistrationStatus.Confirmed;
    public bool ResidentKey { get; set; }
    public uint SignCounter { get; set; }
    public DateTimeOffset AddedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ConfirmedUtc { get; set; }
    public DateTimeOffset? LastUsedUtc { get; set; }
    public DateTimeOffset? LastVerifiedUtc { get; set; }
}

public sealed class AuthenticatorInfo
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "Authenticator";
    public bool IsLocked { get; set; }
    public string Kind { get; set; } = "Unknown";
}

public sealed class TotpEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Issuer { get; set; } = "";
    public string Account { get; set; } = "";
    public string SecretBase32 { get; set; } = "";
    public int Digits { get; set; } = 6;
    public int Period { get; set; } = 30;
    public string Algorithm { get; set; } = "SHA1";
    public DateTimeOffset AddedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RotationDueUtc { get; set; }

    [JsonIgnore]
    public string DisplayName => string.IsNullOrWhiteSpace(Issuer) ? Account : $"{Issuer} · {Account}";
}

public sealed class TpmStatus
{
    public TpmMode Mode { get; set; }
    public bool Present { get; set; }
    public bool Enabled { get; set; }
    public bool Owned { get; set; }
    public string Manufacturer { get; set; } = "Unavailable";
    public string Version { get; set; } = "None";
    public string Detail { get; set; } = "No TPM detected.";
}

public sealed class TpmKeyRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "TPM key";
    public string ProviderKeyName { get; set; } = "";
    public string Algorithm { get; set; } = "RSA-2048";
    public string PublicKeyBase64 { get; set; } = "";
    public string AttestationStatus { get; set; } = "Provider-backed";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class AuditEvent
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Type { get; set; } = "Info";
    public string Message { get; set; } = "";
    public string Outcome { get; set; } = "Success";
}

public sealed class VaultEnvelope
{
    public string Magic { get; set; } = "DFV2";
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
    public byte[] Hmac { get; set; } = [];
}

public sealed class WrappedSecret
{
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
}

public sealed class UnlockedProfile : IDisposable
{
    private byte[]? _masterKey;

    internal UnlockedProfile(ProfileMetadata metadata, VaultData data, byte[] masterKey)
    {
        Metadata = metadata;
        Data = data;
        _masterKey = masterKey;
    }

    public ProfileMetadata Metadata { get; }
    public VaultData Data { get; }
    internal ReadOnlySpan<byte> MasterKey => _masterKey ?? throw new ObjectDisposedException(nameof(UnlockedProfile));
    public bool IsDisposed => _masterKey is null;

    public void Dispose()
    {
        if (_masterKey is null) return;
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(_masterKey);
        _masterKey = null;
        if (Data.AuditSigningPrivateKeyPkcs8 is { } auditPrivateKey)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(auditPrivateKey);
            Data.AuditSigningPrivateKeyPkcs8 = null;
        }
        GC.SuppressFinalize(this);
    }
}

public sealed record ProfileCreationRequest(string Name, string Pin, byte[]? KeyfileBytes, string? RecoveryCode = null);
public sealed record TotpCode(string Code, int SecondsRemaining, double Progress);
public sealed record SignedAuditExport(string CsvPath, string SignaturePath, string PublicKeyPath);

using System.Security.Cryptography;

namespace DarksFIDO2.Core.Security;

internal static class DataValidation
{
    internal const int MinimumPbkdf2Iterations = 200_000;
    internal const int MaximumPbkdf2Iterations = 2_000_000;
    internal const int MaximumProtectedFileBytes = 32 * 1024 * 1024;
    internal const int MaximumPlaintextVaultBytes = 16 * 1024 * 1024;
    internal const int MaximumProfileCount = 1_000;

    public static void ProfileIndex(ProfileIndex index)
    {
        if (index.Profiles is null || index.Profiles.Count > MaximumProfileCount)
            throw Invalid("The profile index contains too many entries.");
        var ids = new HashSet<Guid>();
        foreach (ProfileSummary item in index.Profiles)
        {
            if (item.Id == Guid.Empty || !ids.Add(item.Id)) throw Invalid("The profile index contains an invalid or duplicate identifier.");
            Text(item.Name, 1, 80, "profile name");
        }
        if (index.LastProfileId is Guid last && last != Guid.Empty && !ids.Contains(last)) index.LastProfileId = null;
    }

    public static void Metadata(ProfileMetadata value, Guid expectedId)
    {
        if (value.Id == Guid.Empty || value.Id != expectedId) throw Invalid("The profile metadata identifier is invalid.");
        Text(value.Name, 1, 80, "profile name");
        Exact(value.Salt, 32, "profile salt");
        if (value.Pbkdf2Iterations is < MinimumPbkdf2Iterations or > MaximumPbkdf2Iterations)
            throw Invalid("The profile key-derivation work factor is outside the supported safety range.");
        if (!Enum.IsDefined(value.DeviceProtection)) throw Invalid("The profile protection mode is invalid.");
        Bytes(value.ProtectedWrappedMasterKey, 1, 256 * 1024, "wrapped master key");
        if (value.KeyfileRequired) Exact(value.KeyfileHash, 32, "keyfile hash");
        else if (value.KeyfileHash is { Length: > 0 }) throw Invalid("Unexpected keyfile hash metadata.");
        if (value.DeviceProtection == DeviceProtection.Tpm) Text(value.TpmWrappingKeyName, 1, 256, "TPM wrapping-key name");
        if ((value.RecoverySalt is null) != (value.ProtectedRecoveryWrappedMasterKey is null))
            throw Invalid("The recovery envelope is incomplete.");
        if (value.RecoverySalt is not null)
        {
            Exact(value.RecoverySalt, 32, "recovery salt");
            Bytes(value.ProtectedRecoveryWrappedMasterKey, 1, 256 * 1024, "recovery envelope");
        }
    }

    public static void Vault(VaultData value, Guid? expectedProfileId = null)
    {
        if (value.SchemaVersion != 1) throw Invalid("The vault schema version is unsupported.");
        if (value.ProfileId == Guid.Empty || expectedProfileId is Guid expected && value.ProfileId != expected)
            throw Invalid("The vault is bound to a different profile.");
        Text(value.ProfileName, 1, 80, "profile name");
        if (value.Settings is null || !Enum.IsDefined(value.Settings.Theme) || value.Settings.AutoLockMinutes is < 1 or > 1_440 || value.Settings.HealthReminderDays is < 1 or > 3_650)
            throw Invalid("The vault settings are invalid.");
        Collection(value.FidoKeys, 10_000, "FIDO key records");
        Collection(value.TotpEntries, 10_000, "TOTP entries");
        Collection(value.TpmKeys, 10_000, "TPM key records");
        Collection(value.AuditLog, 100_000, "audit events");

        foreach (FidoKeyRecord item in value.FidoKeys)
        {
            Text(item.Name, 1, 256, "FIDO key name");
            Text(item.AuthenticatorId, 0, 4_096, "authenticator identifier");
            Text(item.CredentialId, 1, 4_096, "credential identifier");
            ValidateBase64(item.CredentialId, 1, 2_048, "credential identifier");
            Text(item.PublicKeyCoseBase64, 0, 8_192, "credential public key");
            if (item.PublicKeyCoseBase64.Length > 0)
                ValidateBase64(item.PublicKeyCoseBase64, 1, 4_096, "credential public key");
            Text(item.Type, 0, 256, "credential type");
            Text(item.Transport, 0, 256, "credential transport");
            Text(item.RpId, 0, 253, "credential relying-party identifier");
            Text(item.UserName, 0, 256, "credential user name");
            if (!Enum.IsDefined(item.RegistrationStatus)) throw Invalid("A FIDO key has an invalid registration state.");
        }
        foreach (TotpEntry item in value.TotpEntries)
        {
            Text(item.Issuer, 0, 256, "TOTP issuer");
            Text(item.Account, 1, 512, "TOTP account");
            Text(item.SecretBase32, 8, 4_096, "TOTP secret");
            if (item.Digits is not (6 or 8) || item.Period is < 5 or > 300 || item.Algorithm is not ("SHA1" or "SHA256" or "SHA512"))
                throw Invalid("A TOTP entry has unsupported generator settings.");
        }
        foreach (TpmKeyRecord item in value.TpmKeys)
        {
            Text(item.Name, 1, 256, "TPM key name");
            Text(item.ProviderKeyName, 1, 512, "TPM provider-key name");
            string suffix = item.ProviderKeyName.StartsWith("DarksFIDO2.Key.", StringComparison.Ordinal)
                ? item.ProviderKeyName["DarksFIDO2.Key.".Length..] : "";
            if (suffix.Length != 32 || !Guid.TryParseExact(suffix, "N", out _)) throw Invalid("A TPM key is outside the Darks FIDO2 namespace.");
            Text(item.PublicKeyBase64, 1, 64 * 1024, "TPM public key");
            ValidateBase64(item.PublicKeyBase64, 1, 16 * 1024, "TPM public key");
        }
        foreach (AuditEvent item in value.AuditLog)
        {
            Text(item.Type, 1, 128, "audit type");
            Text(item.Outcome, 1, 128, "audit outcome");
            Text(item.Message, 0, 8 * 1024, "audit message");
        }
        if (value.AuditSigningPrivateKeyPkcs8 is { Length: > 0 } privateKey) Bytes(privateKey, 1, 16 * 1024, "audit private key");
        if (value.AuditSigningPublicKeySpki is { Length: > 0 } publicKey) Bytes(publicKey, 1, 16 * 1024, "audit public key");
        if ((value.AuditSigningPrivateKeyPkcs8 is null) != (value.AuditSigningPublicKeySpki is null))
            throw Invalid("The audit signing key pair is incomplete.");
    }

    public static void Text(string? value, int minimumLength, int maximumLength, string label)
    {
        if (value is null || value.Length < minimumLength || value.Length > maximumLength || value.IndexOf('\0') >= 0)
            throw Invalid($"The {label} is invalid.");
    }

    public static void Bytes(byte[]? value, int minimumLength, int maximumLength, string label)
    {
        if (value is null || value.Length < minimumLength || value.Length > maximumLength)
            throw Invalid($"The {label} has an invalid length.");
    }

    private static void Exact(byte[]? value, int length, string label)
    {
        if (value is null || value.Length != length) throw Invalid($"The {label} has an invalid length.");
    }

    private static void Collection<T>(List<T>? value, int maximumCount, string label)
    {
        if (value is null || value.Count > maximumCount || value.Any(x => x is null))
            throw Invalid($"The vault contains invalid {label}.");
    }

    private static void ValidateBase64(string value, int minimumBytes, int maximumBytes, string label)
    {
        byte[] decoded;
        try { decoded = Convert.FromBase64String(value); }
        catch (FormatException ex) { throw new CryptographicException($"The {label} is not valid Base64.", ex); }
        try
        {
            if (decoded.Length < minimumBytes || decoded.Length > maximumBytes) throw Invalid($"The {label} has an invalid decoded length.");
        }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    private static CryptographicException Invalid(string message) => new(message);
}

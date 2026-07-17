using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarksFIDO2.Core.Interop;
using DarksFIDO2.Core.Security;

namespace DarksFIDO2.Core.Storage;

public sealed class VaultRepository
{
    private readonly AppPaths _paths;
    private readonly TpmService _tpm;
    private readonly bool _useTpm;
    private readonly object _gate = new();

    public VaultRepository(AppPaths paths, TpmService? tpm = null, bool useTpm = true)
    {
        _paths = paths;
        _tpm = tpm ?? new TpmService();
        _useTpm = useTpm;
    }

    public AppPaths Paths => _paths;

    public ProfileIndex LoadIndex()
    {
        lock (_gate)
        {
            if (!File.Exists(_paths.IndexPath)) return new ProfileIndex();
            try
            {
                byte[] protectedBytes = SecureFile.ReadAllBytes(_paths.IndexPath, 4 * 1024 * 1024);
                byte[] json = DpapiProtector.Unprotect(protectedBytes);
                try
                {
                    ProfileIndex index = JsonSerializer.Deserialize<ProfileIndex>(json, VaultCryptography.JsonOptions) ?? new ProfileIndex();
                    DataValidation.ProfileIndex(index);
                    for (int i = 0; i < index.Profiles.Count; i++)
                    {
                        ProfileMetadata metadata = ReadMetadata(index.Profiles[i].Id);
                        index.Profiles[i] = new ProfileSummary(metadata.Id, metadata.Name, metadata.KeyfileRequired, metadata.CreatedUtc);
                    }
                    return index;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(json);
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("The local profile index could not be decrypted or has been tampered with.", ex);
            }
        }
    }

    public UnlockedProfile CreateProfile(ProfileCreationRequest request)
    {
        string name = request.Name.Trim();
        if (request.Pin.Length < 10) throw new ArgumentException("New profiles require a PIN/passphrase of at least 10 characters.");
        if (request.RecoveryCode is { Length: > 1_024 }) throw new ArgumentException("The recovery code is too long.");
        if (name.Length is < 1 or > 80) throw new ArgumentException("Profile name must contain 1–80 characters.");
        ProfileIndex index = LoadIndex();
        if (index.Profiles.Any(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("A profile with that name already exists.");

        Guid id = Guid.NewGuid();
        string directory = _paths.ProfileDirectory(id);
        Directory.CreateDirectory(directory);
        byte[] masterKey = VaultCryptography.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[]? keyfile = request.KeyfileBytes;
        byte[] factorKey = VaultCryptography.DeriveFactorKey(request.Pin, salt, 600_000, keyfile);
        try
        {
            byte[] factorWrapped = VaultCryptography.WrapMasterKey(masterKey, factorKey, id);
            var metadata = new ProfileMetadata
            {
                Id = id,
                Name = name,
                Salt = salt,
                Pbkdf2Iterations = 600_000,
                KeyfileRequired = keyfile is not null,
                KeyfileHash = keyfile is null ? null : VaultCryptography.ComputeKeyfileHash(keyfile),
                CreatedUtc = DateTimeOffset.UtcNow
            };

            ProtectFactorEnvelope(metadata, factorWrapped);
            CryptographicOperations.ZeroMemory(factorWrapped);

            if (keyfile is not null && !string.IsNullOrWhiteSpace(request.RecoveryCode))
            {
                metadata.RecoverySalt = RandomNumberGenerator.GetBytes(32);
                byte[] recoveryBytes = Encoding.UTF8.GetBytes(request.RecoveryCode);
                byte[] recoveryFactor = VaultCryptography.DeriveFactorKey(request.Pin, metadata.RecoverySalt, metadata.Pbkdf2Iterations, recoveryBytes);
                try
                {
                    byte[] recoveryWrapped = VaultCryptography.WrapMasterKey(masterKey, recoveryFactor, id);
                    metadata.ProtectedRecoveryWrappedMasterKey = ProtectDevice(metadata, recoveryWrapped);
                    CryptographicOperations.ZeroMemory(recoveryWrapped);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recoveryBytes);
                    CryptographicOperations.ZeroMemory(recoveryFactor);
                }
            }

            var data = new VaultData
            {
                ProfileId = id,
                ProfileName = name,
                CreatedUtc = metadata.CreatedUtc,
                AuditLog =
                [
                    new AuditEvent { Type = "Profile", Message = "Encrypted profile created.", Outcome = "Success" }
                ]
            };
            WriteMetadata(metadata);
            WriteVault(id, data, masterKey);
            index.Profiles.Add(new ProfileSummary(id, name, metadata.KeyfileRequired, metadata.CreatedUtc));
            index.LastProfileId = id;
            WriteIndex(index);
            return new UnlockedProfile(metadata, data, masterKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(masterKey);
            try { Directory.Delete(directory, recursive: true); } catch { }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(factorKey);
        }
    }

    public UnlockedProfile Unlock(Guid profileId, string pin, byte[]? keyfile)
    {
        ProfileMetadata metadata = ReadMetadata(profileId);
        if (metadata.KeyfileRequired && keyfile is null)
            throw new CryptographicException("This profile requires its master keyfile in addition to the PIN.");
        if (!metadata.KeyfileRequired) keyfile = null;
        if (metadata.KeyfileHash is not null && keyfile is not null)
        {
            byte[] actual = VaultCryptography.ComputeKeyfileHash(keyfile);
            bool match = CryptographicOperations.FixedTimeEquals(actual, metadata.KeyfileHash);
            CryptographicOperations.ZeroMemory(actual);
            if (!match) throw new CryptographicException("The selected keyfile is not valid for this profile.");
        }

        byte[] factorKey = VaultCryptography.DeriveFactorKey(pin, metadata.Salt, metadata.Pbkdf2Iterations, keyfile);
        return UnlockCore(metadata, factorKey, metadata.ProtectedWrappedMasterKey);
    }

    public UnlockedProfile UnlockWithRecovery(Guid profileId, string pin, string recoveryCode)
    {
        ProfileMetadata metadata = ReadMetadata(profileId);
        if (metadata.ProtectedRecoveryWrappedMasterKey is null || metadata.RecoverySalt is null)
            throw new InvalidOperationException("No recovery code is configured for this profile.");
        byte[] recoveryBytes = Encoding.UTF8.GetBytes(recoveryCode.Trim());
        byte[] factorKey = VaultCryptography.DeriveFactorKey(pin, metadata.RecoverySalt, metadata.Pbkdf2Iterations, recoveryBytes);
        CryptographicOperations.ZeroMemory(recoveryBytes);
        return UnlockCore(metadata, factorKey, metadata.ProtectedRecoveryWrappedMasterKey);
    }

    public void Save(UnlockedProfile profile)
    {
        if (profile.IsDisposed) throw new ObjectDisposedException(nameof(profile));
        if (profile.Metadata.Id == Guid.Empty || profile.Data.ProfileId != profile.Metadata.Id)
            throw new CryptographicException("The unlocked vault is not bound to its profile metadata.");
        if (profile.Data.AuditLog.Count > 100_000)
            profile.Data.AuditLog.RemoveRange(0, profile.Data.AuditLog.Count - 100_000);
        lock (_gate) WriteVault(profile.Metadata.Id, profile.Data, profile.MasterKey);
    }

    public void Rename(UnlockedProfile profile, string newName)
    {
        newName = newName.Trim();
        ProfileIndex existing = LoadIndex();
        if (existing.Profiles.Any(x => x.Id != profile.Metadata.Id && string.Equals(x.Name, newName, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("A profile with that name already exists.");
        if (newName.Length is < 1 or > 80) throw new ArgumentException("Profile name must contain 1–80 characters.");
        profile.Metadata.Name = newName;
        profile.Data.ProfileName = newName;
        profile.Data.AuditLog.Add(new AuditEvent { Type = "Profile", Message = $"Profile renamed to {newName}." });
        WriteMetadata(profile.Metadata);
        Save(profile);
        ProfileIndex index = LoadIndex();
        int i = index.Profiles.FindIndex(x => x.Id == profile.Metadata.Id);
        if (i >= 0) index.Profiles[i] = index.Profiles[i] with { Name = newName };
        WriteIndex(index);
    }

    public void ChangePin(UnlockedProfile profile, string newPin, byte[]? currentKeyfile, string? newRecoveryCode = null)
    {
        ProfileMetadata metadata = profile.Metadata;
        if (newPin.Length < 10) throw new ArgumentException("The new PIN/passphrase must contain at least 10 characters.", nameof(newPin));
        if (metadata.KeyfileRequired && currentKeyfile is null)
            throw new CryptographicException("The current master keyfile is required to change this profile's PIN.");
        if (metadata.KeyfileRequired && metadata.KeyfileHash is not null)
        {
            byte[] actual = VaultCryptography.ComputeKeyfileHash(currentKeyfile!);
            bool match = CryptographicOperations.FixedTimeEquals(actual, metadata.KeyfileHash);
            CryptographicOperations.ZeroMemory(actual);
            if (!match) throw new CryptographicException("The selected keyfile is not valid for this profile.");
        }
        if (newRecoveryCode is { Length: > 1_024 }) throw new ArgumentException("The recovery code is too long.", nameof(newRecoveryCode));
        byte[] newSalt = RandomNumberGenerator.GetBytes(32);
        byte[] factor = VaultCryptography.DeriveFactorKey(newPin, newSalt, metadata.Pbkdf2Iterations, metadata.KeyfileRequired ? currentKeyfile : null);
        try
        {
            byte[] wrapped = VaultCryptography.WrapMasterKey(profile.MasterKey, factor, metadata.Id);
            metadata.Salt = newSalt;
            metadata.ProtectedWrappedMasterKey = ProtectDevice(metadata, wrapped);
            CryptographicOperations.ZeroMemory(wrapped);
            if (metadata.KeyfileRequired && !string.IsNullOrWhiteSpace(newRecoveryCode))
            {
                metadata.RecoverySalt = RandomNumberGenerator.GetBytes(32);
                byte[] recoveryBytes = Encoding.UTF8.GetBytes(newRecoveryCode);
                byte[] recoveryFactor = VaultCryptography.DeriveFactorKey(newPin, metadata.RecoverySalt, metadata.Pbkdf2Iterations, recoveryBytes);
                try
                {
                    byte[] recoveryWrapped = VaultCryptography.WrapMasterKey(profile.MasterKey, recoveryFactor, metadata.Id);
                    metadata.ProtectedRecoveryWrappedMasterKey = ProtectDevice(metadata, recoveryWrapped);
                    CryptographicOperations.ZeroMemory(recoveryWrapped);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recoveryBytes);
                    CryptographicOperations.ZeroMemory(recoveryFactor);
                }
            }
            WriteMetadata(metadata);
            profile.Data.AuditLog.Add(new AuditEvent { Type = "Security", Message = "Profile PIN/passphrase changed." });
            Save(profile);
        }
        finally { CryptographicOperations.ZeroMemory(factor); }
    }

    public void ConfigureKeyfile(UnlockedProfile profile, string pin, byte[]? currentKeyfile, byte[]? newKeyfile, string? recoveryCode)
    {
        // Re-authenticate with the old factors before changing the security policy.
        using (UnlockedProfile verified = Unlock(profile.Metadata.Id, pin, currentKeyfile)) { }
        ProfileMetadata current = profile.Metadata;
        ProfileMetadata metadata = CloneMetadata(current);
        byte[] newSalt = RandomNumberGenerator.GetBytes(32);
        byte[] factor = VaultCryptography.DeriveFactorKey(pin, newSalt, metadata.Pbkdf2Iterations, newKeyfile);
        try
        {
            byte[] wrapped = VaultCryptography.WrapMasterKey(profile.MasterKey, factor, metadata.Id);
            metadata.Salt = newSalt;
            metadata.KeyfileRequired = newKeyfile is not null;
            metadata.KeyfileHash = newKeyfile is null ? null : VaultCryptography.ComputeKeyfileHash(newKeyfile);
            metadata.ProtectedWrappedMasterKey = ProtectDevice(metadata, wrapped);
            CryptographicOperations.ZeroMemory(wrapped);
            metadata.RecoverySalt = null;
            metadata.ProtectedRecoveryWrappedMasterKey = null;
            if (newKeyfile is not null && !string.IsNullOrWhiteSpace(recoveryCode))
            {
                metadata.RecoverySalt = RandomNumberGenerator.GetBytes(32);
                byte[] recoveryBytes = Encoding.UTF8.GetBytes(recoveryCode);
                byte[] recoveryFactor = VaultCryptography.DeriveFactorKey(pin, metadata.RecoverySalt, metadata.Pbkdf2Iterations, recoveryBytes);
                try
                {
                    byte[] recoveryWrapped = VaultCryptography.WrapMasterKey(profile.MasterKey, recoveryFactor, metadata.Id);
                    metadata.ProtectedRecoveryWrappedMasterKey = ProtectDevice(metadata, recoveryWrapped);
                    CryptographicOperations.ZeroMemory(recoveryWrapped);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recoveryBytes);
                    CryptographicOperations.ZeroMemory(recoveryFactor);
                }
            }
            ProfileIndex index = LoadIndex();
            int i = index.Profiles.FindIndex(x => x.Id == metadata.Id);
            if (i >= 0) index.Profiles[i] = index.Profiles[i] with { KeyfileRequired = metadata.KeyfileRequired };
            WriteIndex(index);
            WriteMetadata(metadata);
            CopyMetadata(metadata, current);
            var audit = new AuditEvent
            {
                Type = "Security",
                Message = newKeyfile is null ? "Master keyfile requirement disabled." : "Master keyfile enabled or regenerated."
            };
            profile.Data.AuditLog.Add(audit);
            try { Save(profile); }
            catch { profile.Data.AuditLog.Remove(audit); }
        }
        finally { CryptographicOperations.ZeroMemory(factor); }
    }

    public void Delete(UnlockedProfile profile, string typedProfileName, Action<UnlockedProfile> deleteOwnedKeys)
    {
        ArgumentNullException.ThrowIfNull(deleteOwnedKeys);
        if (!string.Equals(profile.Metadata.Name, typedProfileName, StringComparison.Ordinal))
            throw new InvalidOperationException("The confirmation text does not match the profile name.");
        deleteOwnedKeys(profile);
        Guid id = profile.Metadata.Id;
        string? wrappingKey = profile.Metadata.DeviceProtection == DeviceProtection.Tpm ? profile.Metadata.TpmWrappingKeyName : null;
        ProfileIndex index = LoadIndex();
        if (!index.Profiles.Any(x => x.Id == id))
            throw new InvalidOperationException("The profile is no longer present in the local index.");
        index.Profiles.RemoveAll(x => x.Id == id);
        if (index.LastProfileId == id) index.LastProfileId = index.Profiles.FirstOrDefault()?.Id;

        string profileDirectory = _paths.ProfileDirectory(id);
        string tombstone = Path.Combine(_paths.ProfilesDirectory, $".delete-{id:N}-{Guid.NewGuid():N}");
        profile.Dispose();
        Directory.Move(profileDirectory, tombstone);
        try
        {
            WriteIndex(index);
        }
        catch
        {
            try { Directory.Move(tombstone, profileDirectory); } catch { }
            throw;
        }

        Exception? cleanupError = null;
        try { Directory.Delete(tombstone, recursive: true); }
        catch (Exception ex) { cleanupError = ex; }
        if (!string.IsNullOrWhiteSpace(wrappingKey))
        {
            try { _tpm.DeleteKeyIfPresent(wrappingKey); }
            catch (Exception ex) { cleanupError ??= ex; }
        }
        if (cleanupError is not null)
            throw new IOException("The profile was removed from the application, but Windows could not complete all local cleanup.", cleanupError);
    }

    private UnlockedProfile UnlockCore(ProfileMetadata metadata, byte[] factorKey, byte[] protectedEnvelope)
    {
        try
        {
            byte[] wrapped = UnprotectDevice(metadata, protectedEnvelope);
            byte[] master = VaultCryptography.UnwrapMasterKey(wrapped, factorKey, metadata.Id);
            CryptographicOperations.ZeroMemory(wrapped);
            try
            {
                byte[] envelope = SecureFile.ReadAllBytes(_paths.VaultPath(metadata.Id), DataValidation.MaximumProtectedFileBytes);
                VaultData data;
                try { data = VaultCryptography.DecryptVault(envelope, master, metadata.Id); }
                finally { CryptographicOperations.ZeroMemory(envelope); }
                DataValidation.Vault(data, metadata.Id);
                data.AuditLog.Add(new AuditEvent { Type = "Authentication", Message = "Profile unlocked." });
                var unlocked = new UnlockedProfile(metadata, data, master);
                Save(unlocked);
                ProfileIndex index = LoadIndex();
                index.LastProfileId = metadata.Id;
                WriteIndex(index);
                return unlocked;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(master);
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(factorKey); }
    }

    private void ProtectFactorEnvelope(ProfileMetadata metadata, byte[] factorWrapped)
    {
        TpmStatus status = _tpm.Detect();
        if (_useTpm && status.Mode == TpmMode.Tpm20)
        {
            metadata.TpmWrappingKeyName = $"DarksFIDO2.Vault.{metadata.Id:N}";
            try
            {
                metadata.ProtectedWrappedMasterKey = _tpm.Seal(metadata.TpmWrappingKeyName, factorWrapped);
                metadata.DeviceProtection = DeviceProtection.Tpm;
                return;
            }
            catch
            {
                metadata.TpmWrappingKeyName = null;
            }
        }
        metadata.DeviceProtection = DeviceProtection.Dpapi;
        metadata.ProtectedWrappedMasterKey = DpapiProtector.Protect(factorWrapped);
    }

    private byte[] ProtectDevice(ProfileMetadata metadata, byte[] bytes) => metadata.DeviceProtection switch
    {
        DeviceProtection.Tpm when metadata.TpmWrappingKeyName is not null => _tpm.Seal(metadata.TpmWrappingKeyName, bytes),
        _ => DpapiProtector.Protect(bytes)
    };

    private byte[] UnprotectDevice(ProfileMetadata metadata, byte[] bytes) => metadata.DeviceProtection switch
    {
        DeviceProtection.Tpm when metadata.TpmWrappingKeyName is not null => _tpm.Unseal(metadata.TpmWrappingKeyName, bytes),
        _ => DpapiProtector.Unprotect(bytes)
    };

    private ProfileMetadata ReadMetadata(Guid id)
    {
        if (id == Guid.Empty) throw new CryptographicException("The profile identifier is invalid.");
        byte[] protectedBytes = SecureFile.ReadAllBytes(_paths.MetadataPath(id), 1024 * 1024);
        byte[] json = DpapiProtector.Unprotect(protectedBytes);
        try
        {
            ProfileMetadata metadata = JsonSerializer.Deserialize<ProfileMetadata>(json, VaultCryptography.JsonOptions)
                ?? throw new CryptographicException("Invalid profile metadata.");
            DataValidation.Metadata(metadata, id);
            return metadata;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private void WriteMetadata(ProfileMetadata metadata)
    {
        DataValidation.Metadata(metadata, metadata.Id);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(metadata, VaultCryptography.JsonOptions);
        byte[] protectedBytes = DpapiProtector.Protect(json);
        CryptographicOperations.ZeroMemory(json);
        try { SecureFile.AtomicWrite(_paths.MetadataPath(metadata.Id), protectedBytes); }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private void WriteVault(Guid id, VaultData data, ReadOnlySpan<byte> masterKey)
    {
        DataValidation.Vault(data, id);
        byte[] envelope = VaultCryptography.EncryptVault(data, masterKey);
        try { SecureFile.AtomicWrite(_paths.VaultPath(id), envelope); }
        finally { CryptographicOperations.ZeroMemory(envelope); }
    }

    private void WriteIndex(ProfileIndex index)
    {
        DataValidation.ProfileIndex(index);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(index, VaultCryptography.JsonOptions);
        byte[] protectedBytes = DpapiProtector.Protect(json);
        CryptographicOperations.ZeroMemory(json);
        try { SecureFile.AtomicWrite(_paths.IndexPath, protectedBytes); }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static ProfileMetadata CloneMetadata(ProfileMetadata value) => new()
    {
        Id = value.Id,
        Name = value.Name,
        CreatedUtc = value.CreatedUtc,
        Salt = value.Salt.ToArray(),
        Pbkdf2Iterations = value.Pbkdf2Iterations,
        KeyfileRequired = value.KeyfileRequired,
        KeyfileHash = value.KeyfileHash?.ToArray(),
        DeviceProtection = value.DeviceProtection,
        ProtectedWrappedMasterKey = value.ProtectedWrappedMasterKey.ToArray(),
        TpmWrappingKeyName = value.TpmWrappingKeyName,
        ProtectedRecoveryWrappedMasterKey = value.ProtectedRecoveryWrappedMasterKey?.ToArray(),
        RecoverySalt = value.RecoverySalt?.ToArray()
    };

    private static void CopyMetadata(ProfileMetadata source, ProfileMetadata target)
    {
        target.Name = source.Name;
        target.Salt = source.Salt;
        target.Pbkdf2Iterations = source.Pbkdf2Iterations;
        target.KeyfileRequired = source.KeyfileRequired;
        target.KeyfileHash = source.KeyfileHash;
        target.DeviceProtection = source.DeviceProtection;
        target.ProtectedWrappedMasterKey = source.ProtectedWrappedMasterKey;
        target.TpmWrappingKeyName = source.TpmWrappingKeyName;
        target.ProtectedRecoveryWrappedMasterKey = source.ProtectedRecoveryWrappedMasterKey;
        target.RecoverySalt = source.RecoverySalt;
    }
}

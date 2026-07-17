using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarksFIDO2.Core.Security;

namespace DarksFIDO2.Core.Passkeys;

public sealed class SoftwarePasskeyStore
{
    private const int MaximumStoreBytes = 4 * 1024 * 1024;
    private const int MaximumCredentials = 10_000;
    private const string KeyNamePrefix = "DarksFIDO2.Passkey.";
    private static readonly CngProvider TpmProvider = new("Microsoft Platform Crypto Provider");
    private static readonly CngProvider SoftwareProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private readonly string _storePath;
    private readonly object _gate = new();
    private readonly Mutex _crossProcessGate;

    public SoftwarePasskeyStore(string? root = null)
    {
        root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DarksFIDO2", "PasskeyProvider");
        Directory.CreateDirectory(root);
        _storePath = Path.Combine(root, "credentials.dpapi");
        string mutexSuffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(root))))[..16];
        _crossProcessGate = new Mutex(false, @"Local\DarksFIDO2.PasskeyStore." + mutexSuffix);
    }

    public string StorePath => _storePath;

    public IReadOnlyList<SoftwarePasskeyCredential> List()
    {
        return WithStoreLock(() => Load().Select(Clone).ToArray());
    }

    public SoftwarePasskeyCredential Create(string rpId, string rpName, byte[] userId, string userName, string displayName, Guid profileId)
    {
        ValidateIdentity(rpId, rpName, userId, userName, displayName, profileId);
        byte[] credentialId = RandomNumberGenerator.GetBytes(32);
        string keyName = $"{KeyNamePrefix}{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)))[..16]}.{Convert.ToHexString(credentialId)}";
        bool hardwareBacked = TryCreateKey(keyName, TpmProvider);
        if (!hardwareBacked && !TryCreateKey(keyName, SoftwareProvider)) throw new CryptographicException("Windows could not create a non-exportable passkey key.");

        var credential = new SoftwarePasskeyCredential
        {
            CredentialId = credentialId,
            RpId = rpId,
            RpName = string.IsNullOrWhiteSpace(rpName) ? rpId : rpName,
            UserId = userId.ToArray(),
            UserName = userName,
            UserDisplayName = string.IsNullOrWhiteSpace(displayName) ? userName : displayName,
            ProviderKeyName = keyName,
            HardwareBacked = hardwareBacked,
            ProfileId = profileId,
            RegistrationStatus = PasskeyRegistrationStatus.Pending,
            CreatedUtc = DateTimeOffset.UtcNow
        };
        WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            if (all.Count >= MaximumCredentials) throw new InvalidOperationException("The passkey store has reached its safety limit.");
            all.Add(credential);
            try { Save(all); }
            catch
            {
                try { DeleteKeyIfPresent(credential); } catch { }
                throw;
            }
        });
        return Clone(credential);
    }

    public IReadOnlyList<SoftwarePasskeyCredential> ClaimUnassigned(Guid profileId)
    {
        if (profileId == Guid.Empty) throw new ArgumentException("A profile is required.", nameof(profileId));
        return WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            bool changed = false;
            foreach (SoftwarePasskeyCredential credential in all.Where(c => c.ProfileId is null))
            {
                credential.ProfileId = profileId;
                changed = true;
            }
            if (changed) Save(all);
            return (IReadOnlyList<SoftwarePasskeyCredential>)all.Where(c => c.ProfileId == profileId).Select(Clone).ToArray();
        });
    }

    public SoftwarePasskeyCredential? Find(Guid profileId, string rpId, IEnumerable<byte[]> allowCredentialIds)
    {
        if (profileId == Guid.Empty) return null;
        byte[][] allowed = allowCredentialIds.Select(x => x.ToArray()).ToArray();
        return WithStoreLock(() =>
        {
            SoftwarePasskeyCredential? match = Load().FirstOrDefault(c =>
                c.ProfileId == profileId &&
                string.Equals(c.RpId, rpId, StringComparison.OrdinalIgnoreCase) &&
                (allowed.Length == 0 || allowed.Any(id => CryptographicOperations.FixedTimeEquals(id, c.CredentialId))));
            return match is null ? null : Clone(match);
        });
    }

    public SoftwarePasskeyCredential? Find(Guid profileId, byte[] credentialId)
    {
        if (profileId == Guid.Empty || credentialId is null || credentialId.Length != 32) return null;
        return WithStoreLock(() =>
        {
            SoftwarePasskeyCredential? match = Load().FirstOrDefault(c =>
                c.ProfileId == profileId &&
                CryptographicOperations.FixedTimeEquals(c.CredentialId, credentialId));
            return match is null ? null : Clone(match);
        });
    }

    public bool ConfirmRegistration(Guid profileId, byte[] credentialId)
    {
        if (profileId == Guid.Empty || credentialId is null || credentialId.Length != 32) return false;
        return WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            SoftwarePasskeyCredential? stored = all.FirstOrDefault(c =>
                c.ProfileId == profileId &&
                CryptographicOperations.FixedTimeEquals(c.CredentialId, credentialId));
            if (stored is null) return false;
            if (stored.RegistrationStatus == PasskeyRegistrationStatus.Confirmed) return true;
            stored.RegistrationStatus = PasskeyRegistrationStatus.Confirmed;
            stored.ConfirmedUtc = DateTimeOffset.UtcNow;
            Save(all);
            return true;
        });
    }

    public byte[] PublicCoseKey(SoftwarePasskeyCredential credential)
    {
        using CngKey key = OpenKey(credential);
        byte[] blob = key.Export(CngKeyBlobFormat.EccPublicBlob);
        if (blob.Length < 72) throw new CryptographicException("Invalid P-256 public key blob.");
        uint coordinateLength = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(4, 4));
        if (coordinateLength != 32 || blob.Length < 8 + coordinateLength * 2) throw new CryptographicException("Unexpected P-256 public key size.");
        byte[] x = blob.AsSpan(8, 32).ToArray();
        byte[] y = blob.AsSpan(40, 32).ToArray();
        return CtapCbor.Encode(new Dictionary<object, object?> { [1L] = 2L, [3L] = -7L, [-1L] = 1L, [-2L] = x, [-3L] = y });
    }

    public byte[] Sign(SoftwarePasskeyCredential credential, ReadOnlySpan<byte> data)
    {
        using CngKey key = OpenKey(credential);
        using var ecdsa = new ECDsaCng(key);
        byte[] hash = SHA256.HashData(data);
        try { return ecdsa.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    public uint IncrementCounter(SoftwarePasskeyCredential credential)
    {
        return WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            SoftwarePasskeyCredential stored = all.Single(c =>
                c.ProfileId == credential.ProfileId &&
                string.Equals(c.RpId, credential.RpId, StringComparison.OrdinalIgnoreCase) &&
                CryptographicOperations.FixedTimeEquals(c.CredentialId, credential.CredentialId));
            stored.SignCount = stored.SignCount == uint.MaxValue ? uint.MaxValue : stored.SignCount + 1;
            stored.RegistrationStatus = PasskeyRegistrationStatus.Confirmed;
            stored.ConfirmedUtc ??= DateTimeOffset.UtcNow;
            stored.LastUsedUtc = DateTimeOffset.UtcNow;
            Save(all);
            credential.SignCount = stored.SignCount;
            credential.RegistrationStatus = stored.RegistrationStatus;
            credential.ConfirmedUtc = stored.ConfirmedUtc;
            credential.LastUsedUtc = stored.LastUsedUtc;
            return stored.SignCount;
        });
    }

    public bool Remove(byte[] credentialId)
        => RemoveCore(null, credentialId);

    public bool Remove(Guid profileId, byte[] credentialId)
        => profileId == Guid.Empty ? false : RemoveCore(profileId, credentialId);

    public int RemoveProfile(Guid profileId)
    {
        if (profileId == Guid.Empty) throw new ArgumentException("A profile is required.", nameof(profileId));
        return WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            SoftwarePasskeyCredential[] matches = all.Where(item => item.ProfileId == profileId).ToArray();
            foreach (SoftwarePasskeyCredential match in matches) DeleteKeyIfPresent(match);
            if (matches.Length == 0) return 0;
            all.RemoveAll(item => item.ProfileId == profileId);
            Save(all);
            return matches.Length;
        });
    }

    private bool RemoveCore(Guid? profileId, byte[] credentialId)
    {
        if (credentialId is null || credentialId.Length != 32) return false;
        return WithStoreLock(() =>
        {
            List<SoftwarePasskeyCredential> all = Load();
            SoftwarePasskeyCredential? match = all.FirstOrDefault(c =>
                (profileId is null || c.ProfileId == profileId) &&
                CryptographicOperations.FixedTimeEquals(c.CredentialId, credentialId));
            if (match is null) return false;
            DeleteKeyIfPresent(match);
            all.Remove(match);
            Save(all);
            return true;
        });
    }

    private static bool TryCreateKey(string name, CngProvider provider)
    {
        try
        {
            using CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, name, new CngKeyCreationParameters
            {
                Provider = provider,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing,
                KeyCreationOptions = CngKeyCreationOptions.None
            });
            return true;
        }
        catch (CryptographicException) { return false; }
    }

    private static CngKey OpenKey(SoftwarePasskeyCredential credential) =>
        credential.ProviderKeyName.StartsWith(KeyNamePrefix, StringComparison.Ordinal)
            ? CngKey.Open(credential.ProviderKeyName, credential.HardwareBacked ? TpmProvider : SoftwareProvider)
            : throw new CryptographicException("The passkey provider-key name is invalid.");

    private static void DeleteKeyIfPresent(SoftwarePasskeyCredential credential)
    {
        CngProvider provider = credential.HardwareBacked ? TpmProvider : SoftwareProvider;
        if (!CngKey.Exists(credential.ProviderKeyName, provider)) return;
        using CngKey key = OpenKey(credential);
        key.Delete();
    }

    private List<SoftwarePasskeyCredential> Load()
    {
        if (!File.Exists(_storePath)) return [];
        byte[] protectedBytes = SecureFile.ReadAllBytes(_storePath, MaximumStoreBytes);
        byte[] plaintext = DpapiProtector.Unprotect(protectedBytes);
        try
        {
            List<SoftwarePasskeyCredential> credentials = JsonSerializer.Deserialize<List<SoftwarePasskeyCredential>>(plaintext, VaultCryptography.JsonOptions) ?? [];
            ValidateStore(credentials);
            return credentials;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private void Save(List<SoftwarePasskeyCredential> credentials)
    {
        ValidateStore(credentials);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(credentials, VaultCryptography.JsonOptions);
        byte[] protectedBytes = DpapiProtector.Protect(plaintext);
        try
        {
            SecureFile.AtomicWrite(_storePath, protectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static void ValidateStore(List<SoftwarePasskeyCredential> credentials)
    {
        if (credentials.Count > MaximumCredentials) throw new CryptographicException("The passkey store contains too many credentials.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (SoftwarePasskeyCredential credential in credentials)
        {
            if (credential.CredentialId is null || credential.CredentialId.Length != 32 ||
                credential.UserId is null || credential.UserId.Length is < 1 or > 64 ||
                !ids.Add(Convert.ToHexString(credential.CredentialId)))
                throw new CryptographicException("The passkey store contains an invalid or duplicate credential.");
            ValidateIdentity(credential.RpId, credential.RpName, credential.UserId, credential.UserName,
                credential.UserDisplayName, credential.ProfileId ?? Guid.NewGuid(), allowLegacyProfile: true);
            if (credential.ProviderKeyName is null || credential.ProviderKeyName.Length > 512 ||
                !credential.ProviderKeyName.StartsWith(KeyNamePrefix, StringComparison.Ordinal))
                throw new CryptographicException("The passkey store contains an invalid provider-key name.");
            if (!Enum.IsDefined(credential.RegistrationStatus))
                throw new CryptographicException("The passkey store contains an invalid registration state.");
        }
    }

    private static void ValidateIdentity(string rpId, string rpName, byte[] userId, string userName, string displayName,
        Guid profileId, bool allowLegacyProfile = false)
    {
        if ((!allowLegacyProfile && profileId == Guid.Empty) || userId is null || userId.Length is < 1 or > 64 ||
            !ValidText(rpId, 1, 253) || rpId.Contains("://", StringComparison.Ordinal) || rpId.Contains('/') ||
            rpId.Any(char.IsWhiteSpace) || !ValidText(rpName, 0, 256) || !ValidText(userName, 1, 256) ||
            !ValidText(displayName, 0, 256))
            throw new ArgumentException("Invalid passkey identity or profile.");
    }

    private static bool ValidText(string? value, int minimum, int maximum) =>
        value is not null && value.Length >= minimum && value.Length <= maximum && value.IndexOf('\0') < 0;

    private T WithStoreLock<T>(Func<T> action)
    {
        lock (_gate)
        {
            bool acquired = false;
            try
            {
                try { acquired = _crossProcessGate.WaitOne(TimeSpan.FromSeconds(10)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("The passkey store is busy. Try again in a moment.");
                return action();
            }
            finally { if (acquired) _crossProcessGate.ReleaseMutex(); }
        }
    }

    private void WithStoreLock(Action action) => WithStoreLock(() => { action(); return true; });

    private static SoftwarePasskeyCredential Clone(SoftwarePasskeyCredential source) => new()
    {
        CredentialId = source.CredentialId.ToArray(), RpId = source.RpId, RpName = source.RpName,
        UserId = source.UserId.ToArray(), UserName = source.UserName, UserDisplayName = source.UserDisplayName,
        ProviderKeyName = source.ProviderKeyName, HardwareBacked = source.HardwareBacked,
        ProfileId = source.ProfileId, RegistrationStatus = source.RegistrationStatus,
        SignCount = source.SignCount, CreatedUtc = source.CreatedUtc,
        ConfirmedUtc = source.ConfirmedUtc, LastUsedUtc = source.LastUsedUtc
    };
}

public sealed class SoftwarePasskeyCredential
{
    public byte[] CredentialId { get; set; } = [];
    public string RpId { get; set; } = "";
    public string RpName { get; set; } = "";
    public byte[] UserId { get; set; } = [];
    public string UserName { get; set; } = "";
    public string UserDisplayName { get; set; } = "";
    public string ProviderKeyName { get; set; } = "";
    public bool HardwareBacked { get; set; }
    public Guid? ProfileId { get; set; }
    public PasskeyRegistrationStatus RegistrationStatus { get; set; } = PasskeyRegistrationStatus.Confirmed;
    public uint SignCount { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? ConfirmedUtc { get; set; }
    public DateTimeOffset? LastUsedUtc { get; set; }
}

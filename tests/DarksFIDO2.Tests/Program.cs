using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DarksFIDO2.Core;
using DarksFIDO2.Core.Interop;
using DarksFIDO2.Core.Passkeys;
using DarksFIDO2.Core.Security;
using DarksFIDO2.Core.Storage;

bool requireTpm = args.Contains("--require-tpm", StringComparer.OrdinalIgnoreCase);
var tests = new List<(string Name, Action Test)>
{
    ("RFC 6238 SHA-1 vector", TestTotp),
    ("Custom TOTP interval", TestTotpInterval),
    ("TPM detection", () => TestTpmDetection(requireTpm)),
    ("AES-GCM + HMAC tamper detection", TestVaultCrypto),
    ("Profile PIN + keyfile isolation and recovery", TestProfiles),
    ("Transactional profile deletion", TestProfileDeletion),
    ("Password-encrypted backup integrity", TestBackup),
    ("ECDSA signed audit export", TestAudit),
    ("Audit private key zeroed on lock", TestAuditKeyZeroing)
    ,("CTAP CBOR canonical round trip", TestCtapCbor)
    ,("Virtual passkey lifecycle", () => TestSoftwarePasskey(requireTpm))
    ,("Pending passkey confirmation and rejection cleanup", TestPendingPasskeyLifecycle)
    ,("Virtual passkey active-profile binding", TestPasskeyProfileBinding)
    ,("CTAP parser resource limits", TestCtapLimits)
    ,("Backup envelope work-factor limits", TestBackupLimits)
    ,("Tampered profile work-factor rejection", TestMetadataLimits)
    ,("Stale provider context cleanup", TestStaleProviderContext)
    ,("TOTP input limits", TestTotpLimits)
    ,("Audit CSV formula neutralization", TestAuditCsvInjection)
};

int failures = 0;
foreach ((string name, Action test) in tests)
{
    try { test(); Console.WriteLine("PASS  " + name); }
    catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL  " + name + " — " + ex.Message); }
}
Console.WriteLine($"{tests.Count - failures}/{tests.Count} tests passed");
return failures == 0 ? 0 : 1;

static void TestTotp()
{
    // RFC 6238 Appendix B: secret "12345678901234567890", T=59 => 94287082.
    var entry = new TotpEntry { SecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits = 8, Period = 30, Algorithm = "SHA1" };
    string code = TotpService.GetCode(entry, DateTimeOffset.FromUnixTimeSeconds(59)).Code;
    Assert(code == "94287082", "Unexpected RFC vector: " + code);
}

static void TestTotpInterval()
{
    var entry = new TotpEntry { SecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits = 6, Period = 60, Algorithm = "SHA1" };
    TotpCode code = TotpService.GetCode(entry, DateTimeOffset.FromUnixTimeSeconds(59));
    Assert(code.SecondsRemaining == 1, "The configured 60-second interval was not honored.");
    Assert(code.Progress < 0.02, "The interval progress value is incorrect.");
}

static void TestTpmDetection(bool requireTpm)
{
    var service = new TpmService();
    var timer = Stopwatch.StartNew();
    TpmStatus status = service.RefreshStatus();
    timer.Stop();
    Assert(timer.Elapsed < TimeSpan.FromSeconds(2), $"TPM detection blocked for {timer.ElapsedMilliseconds} ms.");
    Assert(Enum.IsDefined(status.Mode), "TPM detection returned an invalid mode.");
    if (requireTpm)
        Assert(status.Mode == TpmMode.Tpm20, $"Expected this computer's TPM 2.0, detected {status.Version}: {status.Detail}");
    Console.WriteLine($"      TPM {status.Version} ({status.Manufacturer}) detected in {timer.ElapsedMilliseconds} ms");
}

static void TestVaultCrypto()
{
    byte[] key = VaultCryptography.GenerateMasterKey();
    try
    {
        Guid profileId = Guid.NewGuid();
        var data = new VaultData { ProfileId = profileId, ProfileName = "Test" };
        byte[] envelope = VaultCryptography.EncryptVault(data, key);
        VaultEnvelope current = JsonSerializer.Deserialize<VaultEnvelope>(envelope, VaultCryptography.JsonOptions)
            ?? throw new InvalidOperationException("Vault envelope was not created.");
        Assert(current.Magic == "DFV2", "New vault encryption did not use the profile-bound DFV2 format.");
        VaultData roundTrip = VaultCryptography.DecryptVault(envelope, key, profileId);
        Assert(roundTrip.ProfileName == "Test", "Round trip changed the payload.");
        AssertThrows<CryptographicException>(() => VaultCryptography.DecryptVault(envelope, key, Guid.NewGuid()),
            "A vault decrypted under the wrong profile identifier.");

        current.Magic = "DFV9";
        byte[] changedMagic = JsonSerializer.SerializeToUtf8Bytes(current, VaultCryptography.JsonOptions);
        bool integrityCheckedFirst = false;
        try { _ = VaultCryptography.DecryptVault(changedMagic, key, profileId); }
        catch (CryptographicException ex) { integrityCheckedFirst = ex.Message.Contains("integrity", StringComparison.OrdinalIgnoreCase); }
        Assert(integrityCheckedFirst, "The unauthenticated format marker was interpreted before the integrity check.");

        byte[] tampered = envelope.ToArray();
        tampered[tampered.Length / 2] ^= 1;
        bool stopped = false;
        try { _ = VaultCryptography.DecryptVault(tampered, key, profileId); } catch { stopped = true; }
        Assert(stopped, "Tampered envelope was accepted.");

        byte[] legacy = CreateLegacyVaultEnvelope(data, key);
        VaultData migrated = VaultCryptography.DecryptVault(legacy, key, profileId);
        Assert(migrated.ProfileId == profileId, "A valid legacy DFV1 vault could not be migrated.");
        CryptographicOperations.ZeroMemory(changedMagic);
        CryptographicOperations.ZeroMemory(tampered);
        CryptographicOperations.ZeroMemory(legacy);
    }
    finally { CryptographicOperations.ZeroMemory(key); }
}

static void TestProfiles()
{
    string root = TempDirectory();
    byte[] keyfile = VaultCryptography.GenerateKeyfile();
    var repo = new VaultRepository(new AppPaths(root), useTpm: false);
    try
    {
        using (UnlockedProfile created = repo.CreateProfile(new ProfileCreationRequest("Personal", "Correct-Horse-7", keyfile, "R3C0V3RY-CODE-123")))
        {
            created.Data.TotpEntries.Add(new TotpEntry { Issuer = "Test", Account = "me", SecretBase32 = "GEZDGNBVGY3TQOJQ" });
            repo.Save(created);
        }
        ProfileSummary summary = repo.LoadIndex().Profiles.Single();
        bool wrongStopped = false;
        try { using var _ = repo.Unlock(summary.Id, "wrong-pin", keyfile); } catch (CryptographicException) { wrongStopped = true; }
        Assert(wrongStopped, "Wrong PIN unlocked the vault.");
        byte[] wrongFile = RandomNumberGenerator.GetBytes(64);
        bool fileStopped = false;
        try { using var _ = repo.Unlock(summary.Id, "Correct-Horse-7", wrongFile); } catch (CryptographicException) { fileStopped = true; }
        Assert(fileStopped, "Wrong keyfile unlocked the vault.");
        using (UnlockedProfile opened = repo.Unlock(summary.Id, "Correct-Horse-7", keyfile)) Assert(opened.Data.TotpEntries.Count == 1, "Encrypted data was not restored.");
        using (UnlockedProfile recovered = repo.UnlockWithRecovery(summary.Id, "Correct-Horse-7", "R3C0V3RY-CODE-123")) Assert(recovered.Data.ProfileName == "Personal", "Recovery unlock failed.");
        using (UnlockedProfile opened = repo.Unlock(summary.Id, "Correct-Horse-7", keyfile))
            AssertThrows<CryptographicException>(() => repo.ChangePin(opened, "A-New-Secure-Passphrase", null), "A keyfile profile accepted a PIN change without its keyfile.");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(keyfile);
        Directory.Delete(root, true);
    }
}

static void TestProfileDeletion()
{
    string root = TempDirectory();
    var repo = new VaultRepository(new AppPaths(root), useTpm: false);
    try
    {
        UnlockedProfile profile = repo.CreateProfile(new ProfileCreationRequest("Delete me", "Delete-Profile-7", null, null));
        Guid id = profile.Metadata.Id;
        string profileDirectory = repo.Paths.ProfileDirectory(id);
        repo.Delete(profile, "Delete me");
        Assert(profile.IsDisposed, "Deleted profile key material remained unlocked.");
        Assert(!Directory.Exists(profileDirectory), "Deleted profile files remained in the active profile directory.");
        ProfileIndex index = repo.LoadIndex();
        Assert(index.Profiles.Count == 0 && index.LastProfileId is null, "The deleted profile remained in the profile index.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestBackup()
{
    string root = TempDirectory();
    string path = Path.Combine(root, "test.dfbackup");
    try
    {
        var data = new VaultData { ProfileId = Guid.NewGuid(), ProfileName = "Backup test", TotpEntries = [new TotpEntry { Account = "A", SecretBase32 = "GEZDGNBVGY3TQOJQ" }] };
        var service = new VaultBackupService();
        service.Export(data, "long-backup-password", path);
        Assert(service.Import(path, "long-backup-password").TotpEntries.Count == 1, "Backup round trip failed.");
        byte[] bytes = File.ReadAllBytes(path); bytes[^20] ^= 1; File.WriteAllBytes(path, bytes);
        bool stopped = false; try { _ = service.Import(path, "long-backup-password"); } catch { stopped = true; }
        Assert(stopped, "Tampered backup was accepted.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestAudit()
{
    string root = TempDirectory(); string csv = Path.Combine(root, "audit.csv");
    try
    {
        var data = new VaultData { AuditLog = [new AuditEvent { Type = "Test", Message = "Signed event" }] };
        var service = new AuditExportService(); SignedAuditExport export = service.ExportSignedCsv(data, csv);
        Assert(service.Verify(export.CsvPath, export.SignaturePath, export.PublicKeyPath), "Valid signature failed.");
        File.AppendAllText(export.CsvPath, "tampered");
        Assert(!service.Verify(export.CsvPath, export.SignaturePath, export.PublicKeyPath), "Tampered audit export verified.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestAuditKeyZeroing()
{
    string root = TempDirectory();
    var repository = new VaultRepository(new AppPaths(root), useTpm: false);
    UnlockedProfile profile = repository.CreateProfile(new ProfileCreationRequest("Audit memory", "Correct-Horse-7", null));
    try
    {
        _ = new AuditExportService().ExportSignedCsv(profile.Data, Path.Combine(root, "audit.csv"));
        repository.Save(profile);
        byte[] privateKeyReference = profile.Data.AuditSigningPrivateKeyPkcs8
            ?? throw new InvalidOperationException("Audit signing key was not created.");
        profile.Dispose();
        Assert(profile.Data.AuditSigningPrivateKeyPkcs8 is null, "The disposed vault retained its audit private-key reference.");
        Assert(privateKeyReference.All(value => value == 0), "The disposed vault left audit private-key bytes in managed memory.");
    }
    finally
    {
        profile.Dispose();
        Directory.Delete(root, true);
    }
}

static void TestCtapCbor()
{
    byte[] hash = RandomNumberGenerator.GetBytes(32);
    var input = new Dictionary<object, object?>
    {
        [1L] = hash,
        [2L] = new Dictionary<object, object?> { ["id"] = "example.com", ["name"] = "Example" },
        [3L] = new List<object?> { -7L, true, "public-key" }
    };
    Dictionary<object, object?> decoded = CtapCbor.Map(CtapCbor.Decode(CtapCbor.Encode(input)));
    Assert(CryptographicOperations.FixedTimeEquals(CtapCbor.Bytes(decoded[1L]), hash), "CBOR byte string changed.");
    Assert(CtapCbor.Text(CtapCbor.Map(decoded[2L])["id"]) == "example.com", "CBOR map changed.");
}

static void TestSoftwarePasskey(bool requireTpm)
{
    string root = TempDirectory();
    var store = new SoftwarePasskeyStore(root);
    SoftwarePasskeyCredential? credential = null;
    Guid profileId = Guid.NewGuid();
    try
    {
        credential = store.Create("example.com", "Example", RandomNumberGenerator.GetBytes(32), "user@example.com", "Test User", profileId);
        if (requireTpm) Assert(credential.HardwareBacked, "Expected the passkey private key to use this computer's TPM.");
        Assert(credential.RegistrationStatus == PasskeyRegistrationStatus.Pending, "A newly created site passkey was presented as confirmed before the relying party accepted it.");
        Assert(store.PublicCoseKey(credential).Length > 60, "COSE public key was not generated.");
        Assert(store.Sign(credential, RandomNumberGenerator.GetBytes(64)).Length > 60, "TPM passkey did not sign.");
        Assert(store.Find(profileId, "example.com", [credential.CredentialId]) is not null, "Stored passkey was not found.");
        Assert(store.IncrementCounter(credential) == 1, "Passkey counter was not persisted.");
        Assert(store.Find(profileId, credential.CredentialId)?.RegistrationStatus == PasskeyRegistrationStatus.Confirmed, "A successful assertion did not confirm the pending site registration.");
    }
    finally
    {
        if (credential is not null) store.Remove(credential.CredentialId);
        Directory.Delete(root, true);
    }
}

static void TestPendingPasskeyLifecycle()
{
    string root = TempDirectory();
    var store = new SoftwarePasskeyStore(root);
    Guid profileId = Guid.NewGuid();
    SoftwarePasskeyCredential? rejected = null;
    SoftwarePasskeyCredential? accepted = null;
    try
    {
        rejected = store.Create("accounts.google.com", "Google", RandomNumberGenerator.GetBytes(32), "rejected@example.com", "Rejected", profileId);
        Assert(rejected.RegistrationStatus == PasskeyRegistrationStatus.Pending, "The Google registration did not start as pending.");
        Assert(store.Remove(profileId, rejected.CredentialId), "A rejected pending credential could not be removed.");
        Assert(store.Find(profileId, rejected.CredentialId) is null, "A rejected credential remained in the provider store.");
        rejected = null;

        accepted = store.Create("accounts.google.com", "Google", RandomNumberGenerator.GetBytes(32), "accepted@example.com", "Accepted", profileId);
        Assert(store.ConfirmRegistration(profileId, accepted.CredentialId), "A confirmed site registration could not be marked complete.");
        SoftwarePasskeyCredential confirmed = store.Find(profileId, accepted.CredentialId) ?? throw new InvalidOperationException("Confirmed credential disappeared.");
        Assert(confirmed.RegistrationStatus == PasskeyRegistrationStatus.Confirmed && confirmed.ConfirmedUtc is not null,
            "The confirmed state was not persisted.");
    }
    finally
    {
        if (rejected is not null) store.Remove(profileId, rejected.CredentialId);
        if (accepted is not null) store.Remove(profileId, accepted.CredentialId);
        Directory.Delete(root, true);
    }
}

static void TestPasskeyProfileBinding()
{
    string root = TempDirectory();
    var context = new PasskeyProviderContext(root);
    var store = new SoftwarePasskeyStore(root);
    SoftwarePasskeyCredential? firstCredential = null;
    SoftwarePasskeyCredential? secondCredential = null;
    Guid firstProfileId = Guid.NewGuid();
    Guid secondProfileId = Guid.NewGuid();
    try
    {
        context.SetActiveProfile(firstProfileId);
        Assert(context.GetActiveProfileId() == firstProfileId, "The active profile marker was not restored.");
        firstCredential = store.Create("accounts.google.com", "Google", RandomNumberGenerator.GetBytes(32), "first@example.com", "First", firstProfileId);
        secondCredential = store.Create("accounts.google.com", "Google", RandomNumberGenerator.GetBytes(32), "second@example.com", "Second", secondProfileId);

        Assert(store.Find(firstProfileId, "accounts.google.com", [])?.UserName == "first@example.com", "The first profile did not resolve its own passkey.");
        Assert(store.Find(secondProfileId, "accounts.google.com", [])?.UserName == "second@example.com", "The second profile reused the first profile's passkey.");
        Assert(store.Find(secondProfileId, "accounts.google.com", [firstCredential.CredentialId]) is null, "A credential ID from another profile crossed the profile boundary.");

        context.Clear(firstProfileId);
        Assert(context.GetActiveProfileId() is null, "Locking did not clear the active profile marker.");
    }
    finally
    {
        if (firstCredential is not null) store.Remove(firstCredential.CredentialId);
        if (secondCredential is not null) store.Remove(secondCredential.CredentialId);
        Directory.Delete(root, true);
    }
}

static void TestCtapLimits()
{
    AssertThrows<FormatException>(() => CtapCbor.Decode(new byte[CtapCbor.MaximumDocumentBytes + 1]), "Oversized CTAP CBOR was accepted.");
    byte[] nested = Enumerable.Repeat((byte)0x81, CtapCbor.MaximumNestingDepth + 2).Append((byte)0xF6).ToArray();
    AssertThrows<FormatException>(() => CtapCbor.Decode(nested), "Excessively nested CTAP CBOR was accepted.");
    AssertThrows<FormatException>(() => CtapCbor.Decode([0x9A, 0xFF, 0xFF, 0xFF, 0xFF]), "A hostile CBOR collection count was accepted.");
    AssertThrows<FormatException>(() => CtapCbor.Decode([0x62, 0xC3, 0x28]), "Invalid UTF-8 in CTAP text was accepted.");
    AssertThrows<FormatException>(() => CtapCbor.Decode([0xA2, 0x01, 0x01, 0x01, 0x02]), "Duplicate CTAP map keys were accepted.");
}

static void TestBackupLimits()
{
    string root = TempDirectory();
    string path = Path.Combine(root, "hostile.dfbackup");
    try
    {
        var service = new VaultBackupService();
        service.Export(new VaultData { ProfileId = Guid.NewGuid(), ProfileName = "Bounded" }, "long-backup-password", path);
        JsonObject envelope = JsonNode.Parse(File.ReadAllBytes(path))?.AsObject() ?? throw new InvalidOperationException("Backup JSON was not created.");
        envelope["Iterations"] = int.MaxValue;
        File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(envelope));
        var timer = Stopwatch.StartNew();
        AssertThrows<CryptographicException>(() => service.Import(path, "long-backup-password"), "A hostile backup PBKDF2 work factor was accepted.");
        timer.Stop();
        Assert(timer.Elapsed < TimeSpan.FromSeconds(2), "Hostile backup parameters consumed excessive CPU time.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestMetadataLimits()
{
    string root = TempDirectory();
    var paths = new AppPaths(root);
    var repository = new VaultRepository(paths, useTpm: false);
    Guid id;
    using (UnlockedProfile profile = repository.CreateProfile(new ProfileCreationRequest("Metadata", "Correct-Horse-7", null))) id = profile.Metadata.Id;
    try
    {
        string path = paths.MetadataPath(id);
        byte[] protectedBytes = File.ReadAllBytes(path);
        byte[] json = DpapiProtector.Unprotect(protectedBytes);
        JsonObject metadata = JsonNode.Parse(json)?.AsObject() ?? throw new InvalidOperationException("Metadata JSON was not created.");
        metadata["Pbkdf2Iterations"] = int.MaxValue;
        byte[] modified = JsonSerializer.SerializeToUtf8Bytes(metadata);
        byte[] reprotected = DpapiProtector.Protect(modified);
        File.WriteAllBytes(path, reprotected);
        CryptographicOperations.ZeroMemory(protectedBytes);
        CryptographicOperations.ZeroMemory(json);
        CryptographicOperations.ZeroMemory(modified);
        CryptographicOperations.ZeroMemory(reprotected);
        var timer = Stopwatch.StartNew();
        AssertThrows<CryptographicException>(() => repository.Unlock(id, "Correct-Horse-7", null), "A hostile profile PBKDF2 work factor was accepted.");
        timer.Stop();
        Assert(timer.Elapsed < TimeSpan.FromSeconds(2), "Hostile profile metadata consumed excessive CPU time.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestStaleProviderContext()
{
    string root = TempDirectory();
    try
    {
        var context = new PasskeyProviderContext(root);
        Guid profileId = Guid.NewGuid();
        context.SetActiveProfile(profileId);
        string path = Path.Combine(root, "active-profile.dpapi");
        byte[] protectedBytes = File.ReadAllBytes(path);
        byte[] json = DpapiProtector.Unprotect(protectedBytes);
        JsonObject marker = JsonNode.Parse(json)?.AsObject() ?? throw new InvalidOperationException("Context JSON was not created.");
        marker["UpdatedUtc"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("O");
        byte[] modified = JsonSerializer.SerializeToUtf8Bytes(marker);
        byte[] reprotected = DpapiProtector.Protect(modified);
        File.WriteAllBytes(path, reprotected);
        CryptographicOperations.ZeroMemory(protectedBytes);
        CryptographicOperations.ZeroMemory(json);
        CryptographicOperations.ZeroMemory(modified);
        CryptographicOperations.ZeroMemory(reprotected);
        Assert(context.GetActiveProfileId() is null, "An expired profile marker was treated as active.");
        context.Clear(profileId);
        Assert(!File.Exists(path), "An expired profile marker could not be cleared.");
    }
    finally { Directory.Delete(root, true); }
}

static void TestTotpLimits()
{
    AssertThrows<FormatException>(() => TotpService.DecodeBase32(new string('A', 9_000)), "An oversized TOTP secret was accepted.");
    AssertThrows<FormatException>(() => TotpService.ParseOtpAuthUri("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQ&secret=GEZDGNBVGY3TQOJQ"), "Duplicate TOTP URI parameters were accepted.");
    AssertThrows<ArgumentException>(() => TotpService.GetCode(new TotpEntry { SecretBase32 = "GEZDGNBVGY3TQOJQ", Algorithm = "MD5" }), "An unsupported TOTP algorithm was silently downgraded.");
}

static void TestAuditCsvInjection()
{
    string root = TempDirectory();
    try
    {
        var data = new VaultData { AuditLog = [new AuditEvent { Type = "Test", Message = "=HYPERLINK(\"https://example.invalid\")" }] };
        SignedAuditExport export = new AuditExportService().ExportSignedCsv(data, Path.Combine(root, "audit.csv"));
        string csv = File.ReadAllText(export.CsvPath);
        Assert(csv.Contains("\"'=HYPERLINK", StringComparison.Ordinal), "A spreadsheet formula was not neutralized in the audit CSV.");
        Assert(new AuditExportService().Verify(export.CsvPath, export.SignaturePath, export.PublicKeyPath), "The neutralized audit CSV signature failed.");
    }
    finally { Directory.Delete(root, true); }
}

static byte[] CreateLegacyVaultEnvelope(VaultData data, ReadOnlySpan<byte> masterKey)
{
    byte[] aad = Encoding.UTF8.GetBytes("DarksFIDO2:vault:v1");
    byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(data, VaultCryptography.JsonOptions);
    byte[] encKey = VaultCryptography.Hkdf(masterKey, [], "DarksFIDO2:vault:encryption", 32);
    byte[] macKey = VaultCryptography.Hkdf(masterKey, [], "DarksFIDO2:vault:integrity", 32);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[16];
    byte[] macInput = [];
    try
    {
        using (var aes = new AesGcm(encKey, 16))
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        macInput = Combine(aad, nonce, ciphertext, tag);
        byte[] hmac = HMACSHA256.HashData(macKey, macInput);
        return JsonSerializer.SerializeToUtf8Bytes(new VaultEnvelope
        {
            Magic = "DFV1",
            Nonce = nonce,
            Ciphertext = ciphertext,
            Tag = tag,
            Hmac = hmac
        }, VaultCryptography.JsonOptions);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(encKey);
        CryptographicOperations.ZeroMemory(macKey);
        if (macInput.Length > 0) CryptographicOperations.ZeroMemory(macInput);
    }
}

static byte[] Combine(params byte[][] parts)
{
    byte[] result = new byte[parts.Sum(part => part.Length)];
    int offset = 0;
    foreach (byte[] part in parts)
    {
        part.CopyTo(result, offset);
        offset += part.Length;
    }
    return result;
}

static string TempDirectory()
{
    string path = Path.Combine(Path.GetTempPath(), "DarksFIDO2-Tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path); return path;
}

static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
static void AssertThrows<T>(Action action, string message) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException(message);
}

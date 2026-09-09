using DarksFIDO2.Core.Interop;
using DarksFIDO2.Core.Passkeys;

namespace DarksFIDO2.Core.Storage;

public sealed class ProfileDeletionService
{
    private readonly SoftwarePasskeyStore _providerStore;
    private readonly Action<SoftwarePasskeyCredential> _removeProviderMetadata;
    private readonly Action<FidoKeyRecord> _deletePlatformCredential;
    private readonly Action<string> _deleteTpmKey;

    public ProfileDeletionService(
        SoftwarePasskeyStore? providerStore = null,
        Action<SoftwarePasskeyCredential>? removeProviderMetadata = null,
        Action<FidoKeyRecord>? deletePlatformCredential = null,
        Action<string>? deleteTpmKey = null)
    {
        _providerStore = providerStore ?? new SoftwarePasskeyStore();
        _removeProviderMetadata = removeProviderMetadata ?? PasskeyProviderService.RemoveCredentialMetadata;
        WebAuthnService webAuthn = new();
        TpmService tpm = new();
        _deletePlatformCredential = deletePlatformCredential ?? webAuthn.DeletePlatformCredentialIfPresent;
        _deleteTpmKey = deleteTpmKey ?? tpm.DeleteKeyIfPresent;
    }

    public void DeleteOwnedKeys(UnlockedProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.IsDisposed) throw new ObjectDisposedException(nameof(profile));

        Guid profileId = profile.Metadata.Id;
        var failures = new List<Exception>();
        IReadOnlyList<SoftwarePasskeyCredential> providerCredentials;
        try { providerCredentials = _providerStore.List().Where(item => item.ProfileId == profileId).ToArray(); }
        catch (Exception ex)
        {
            throw new IOException("The virtual-passkey store could not be read, so profile deletion stopped before removing the vault.", ex);
        }

        foreach (SoftwarePasskeyCredential credential in providerCredentials)
        {
            try { _removeProviderMetadata(credential); }
            catch (Exception ex) { failures.Add(new IOException($"Windows metadata for passkey {Convert.ToHexString(credential.CredentialId)} could not be removed.", ex)); }
        }
        if (failures.Count == 0)
        {
            try { _providerStore.RemoveProfile(profileId); }
            catch (Exception ex) { failures.Add(new IOException("The profile's virtual-passkey private keys could not all be removed.", ex)); }
        }

        foreach (FidoKeyRecord credential in profile.Data.FidoKeys.Where(item =>
                     item.AuthenticatorId != "DarksFIDO2.Provider" &&
                     item.Type.Contains("Platform", StringComparison.OrdinalIgnoreCase)))
        {
            try { _deletePlatformCredential(credential); }
            catch (Exception ex) { failures.Add(new IOException($"Platform credential '{credential.Name}' could not be removed.", ex)); }
        }

        foreach (TpmKeyRecord key in profile.Data.TpmKeys)
        {
            try { _deleteTpmKey(key.ProviderKeyName); }
            catch (Exception ex) { failures.Add(new IOException($"TPM key '{key.Name}' could not be removed.", ex)); }
        }

        if (failures.Count != 0)
            throw new AggregateException(
                "Profile deletion stopped because one or more owned credentials could not be removed. The encrypted profile was kept so cleanup can be retried.",
                failures);
    }
}

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace DarksFIDO2.Core.Interop;

public sealed class TpmService
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const int Success = 0;
    private const int NcryptPadOaepFlag = 0x4;
    private const int NcryptOverwriteKeyFlag = 0x80;
    private const int NcryptAllowDecryptFlag = 0x1;
    private const int NcryptAllowSigningFlag = 0x2;
    private readonly object _statusGate = new();
    private TpmStatus? _cachedStatus;

    public TpmStatus Detect()
    {
        lock (_statusGate) return _cachedStatus ??= ProbeStatus();
    }

    public TpmStatus RefreshStatus()
    {
        lock (_statusGate) return _cachedStatus = ProbeStatus();
    }

    private static TpmStatus ProbeStatus()
    {
        try
        {
            var device = new TpmDeviceInfo();
            uint result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TpmDeviceInfo>(), ref device);
            if (result == 0)
            {
                TpmMode mode = device.tpmVersion == 2 ? TpmMode.Tpm20 : TpmMode.Tpm12;
                string manufacturer = "TPM device";
                string firmware = "";
                bool readyForStorage = true;
                bool readyForAttestation = false;
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM\WMI");
                    if (key?.GetValue("TaskManufacturerId") is int manufacturerId)
                    {
                        Span<byte> bytes = stackalloc byte[4];
                        BinaryPrimitives.WriteUInt32BigEndian(bytes, unchecked((uint)manufacturerId));
                        string id = Encoding.ASCII.GetString(bytes).TrimEnd('\0', ' ');
                        if (!string.IsNullOrWhiteSpace(id)) manufacturer = id;
                    }
                    firmware = Convert.ToString(key?.GetValue("TaskFirmwareVersion")) ?? "";
                    readyForStorage = Convert.ToInt32(key?.GetValue("TaskReadyForStorage") ?? 1) != 0;
                    readyForAttestation = Convert.ToInt32(key?.GetValue("TaskReadyForAttestation") ?? 0) != 0;
                }
                catch { }

                string version = mode == TpmMode.Tpm20 ? "2.0" : "1.2";
                string readiness = readyForAttestation ? "storage and attestation ready" : readyForStorage ? "storage ready" : "present but not provisioned";
                return new TpmStatus
                {
                    Mode = mode,
                    Present = true,
                    Enabled = readyForStorage,
                    Owned = readyForStorage,
                    Manufacturer = string.IsNullOrWhiteSpace(firmware) ? manufacturer : $"{manufacturer} · firmware {firmware}",
                    Version = version,
                    Detail = mode == TpmMode.Tpm20
                        ? $"TPM 2.0 detected through Windows TPM Base Services ({readiness}). Hardware-backed keys use Microsoft Platform Crypto Provider."
                        : "TPM 1.2 detected through Windows TPM Base Services. Legacy RSA/SHA-1 reduced-security mode applies."
                };
            }
        }
        catch
        {
            // The no-TPM result below is the safe fallback when TBS is absent.
        }

        return new TpmStatus
        {
            Mode = TpmMode.None,
            Present = false,
            Enabled = false,
            Owned = false,
            Manufacturer = "Unavailable",
            Version = "None",
            Detail = "No usable TPM was detected. Vault protection uses DPAPI plus the PIN-derived key."
        };
    }

    public byte[] Seal(string keyName, ReadOnlySpan<byte> data)
    {
        ValidateOwnedKeyName(keyName, wrappingKey: true);
        if (data.IsEmpty || data.Length > 190) throw new CryptographicException("The TPM wrapping payload has an invalid length.");
        IntPtr provider = OpenProvider();
        IntPtr key = IntPtr.Zero;
        bool createAttempted = false;
        try
        {
            int status = NCryptOpenKey(provider, out key, keyName, 0, 0);
            if (status != Success)
            {
                createAttempted = true;
                Check(NCryptCreatePersistedKey(provider, out key, "RSA", keyName, 0, 0), "create TPM wrapping key");
                SetIntProperty(key, "Length", 2048);
                SetIntProperty(key, "Key Usage", NcryptAllowDecryptFlag);
                Check(NCryptFinalizeKey(key, 0), "finalize TPM wrapping key");
            }
            return TransformOaep(key, data, encrypt: true);
        }
        catch
        {
            if (createAttempted) TryDeletePartialKey(provider, keyName, ref key);
            throw;
        }
        finally
        {
            if (key != IntPtr.Zero) NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }
    }

    public byte[] Unseal(string keyName, ReadOnlySpan<byte> data)
    {
        ValidateOwnedKeyName(keyName, wrappingKey: true);
        if (data.Length is < 128 or > 512) throw new CryptographicException("The TPM wrapped payload has an invalid length.");
        IntPtr provider = OpenProvider();
        IntPtr key = IntPtr.Zero;
        try
        {
            Check(NCryptOpenKey(provider, out key, keyName, 0, 0), "open TPM wrapping key");
            return TransformOaep(key, data, encrypt: false);
        }
        finally
        {
            if (key != IntPtr.Zero) NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }
    }

    public TpmKeyRecord GenerateKey(string displayName, bool ecc, TpmMode mode)
    {
        if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 256 || displayName.IndexOf('\0') >= 0)
            throw new ArgumentException("The TPM key name is invalid.", nameof(displayName));
        if (mode == TpmMode.None) throw new InvalidOperationException("No TPM is available.");
        if (mode == TpmMode.Tpm12 && ecc) throw new InvalidOperationException("TPM 1.2 does not support ECC in this application.");

        string keyName = $"DarksFIDO2.Key.{Guid.NewGuid():N}";
        string algorithm = ecc ? "ECDSA_P256" : "RSA";
        IntPtr provider = OpenProvider();
        IntPtr key = IntPtr.Zero;
        try
        {
            Check(NCryptCreatePersistedKey(provider, out key, algorithm, keyName, 0, 0), "create TPM key");
            if (!ecc) SetIntProperty(key, "Length", 2048);
            SetIntProperty(key, "Key Usage", NcryptAllowSigningFlag | (ecc ? 0 : NcryptAllowDecryptFlag));
            Check(NCryptFinalizeKey(key, 0), "finalize TPM key");
            byte[] publicBlob = Export(key, ecc ? "ECCPUBLICBLOB" : "RSAPUBLICBLOB");
            return new TpmKeyRecord
            {
                Name = displayName,
                ProviderKeyName = keyName,
                Algorithm = ecc ? "ECC P-256 / SHA-256" : mode == TpmMode.Tpm12 ? "RSA-2048 / SHA-1 (legacy)" : "RSA-2048 / SHA-256",
                PublicKeyBase64 = Convert.ToBase64String(publicBlob),
                AttestationStatus = "Non-exportable key created by Microsoft Platform Crypto Provider",
                CreatedUtc = DateTimeOffset.UtcNow
            };
        }
        catch
        {
            TryDeletePartialKey(provider, keyName, ref key);
            throw;
        }
        finally
        {
            if (key != IntPtr.Zero) NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }
    }

    public void DeleteKey(string providerKeyName)
    {
        ValidateOwnedKeyName(providerKeyName, wrappingKey: providerKeyName?.StartsWith("DarksFIDO2.Vault.", StringComparison.Ordinal) == true);
        IntPtr provider = OpenProvider();
        IntPtr key = IntPtr.Zero;
        try
        {
            Check(NCryptOpenKey(provider, out key, providerKeyName!, 0, 0), "open TPM key");
            Check(NCryptDeleteKey(key, 0), "delete TPM key");
            key = IntPtr.Zero;
        }
        finally
        {
            if (key != IntPtr.Zero) NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }
    }

    public void DeleteKeyIfPresent(string providerKeyName)
    {
        ValidateOwnedKeyName(providerKeyName, wrappingKey: providerKeyName?.StartsWith("DarksFIDO2.Vault.", StringComparison.Ordinal) == true);
        IntPtr provider = OpenProvider();
        IntPtr key = IntPtr.Zero;
        try
        {
            int status = NCryptOpenKey(provider, out key, providerKeyName!, 0, 0);
            if (status == unchecked((int)0x80090016)) return; // NTE_BAD_KEYSET: already absent.
            Check(status, "open TPM key");
            Check(NCryptDeleteKey(key, 0), "delete TPM key");
            key = IntPtr.Zero;
        }
        finally
        {
            if (key != IntPtr.Zero) NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }
    }

    private static void ValidateOwnedKeyName(string keyName, bool wrappingKey)
    {
        string prefix = wrappingKey ? "DarksFIDO2.Vault." : "DarksFIDO2.Key.";
        string suffix = keyName is not null && keyName.StartsWith(prefix, StringComparison.Ordinal) ? keyName[prefix.Length..] : "";
        if (suffix.Length != 32 || !Guid.TryParseExact(suffix, "N", out _))
            throw new CryptographicException("The TPM key name is outside the Darks FIDO2 namespace.");
    }

    private static IntPtr OpenProvider()
    {
        Check(NCryptOpenStorageProvider(out IntPtr provider, ProviderName, 0), "open Microsoft Platform Crypto Provider");
        return provider;
    }

    private static byte[] TransformOaep(IntPtr key, ReadOnlySpan<byte> input, bool encrypt)
    {
        byte[] bytes = input.ToArray();
        IntPtr algorithm = Marshal.StringToHGlobalUni("SHA256");
        IntPtr padding = IntPtr.Zero;
        try
        {
            var info = new OaepPaddingInfo { pszAlgId = algorithm, pbLabel = IntPtr.Zero, cbLabel = 0 };
            padding = Marshal.AllocHGlobal(Marshal.SizeOf<OaepPaddingInfo>());
            Marshal.StructureToPtr(info, padding, false);
            int status = encrypt
                ? NCryptEncrypt(key, bytes, bytes.Length, padding, null, 0, out int required, NcryptPadOaepFlag)
                : NCryptDecrypt(key, bytes, bytes.Length, padding, null, 0, out required, NcryptPadOaepFlag);
            Check(status, encrypt ? "size TPM encryption" : "size TPM decryption");
            byte[] output = new byte[required];
            status = encrypt
                ? NCryptEncrypt(key, bytes, bytes.Length, padding, output, output.Length, out int written, NcryptPadOaepFlag)
                : NCryptDecrypt(key, bytes, bytes.Length, padding, output, output.Length, out written, NcryptPadOaepFlag);
            Check(status, encrypt ? "TPM encryption" : "TPM decryption");
            return written == output.Length ? output : output[..written];
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            if (padding != IntPtr.Zero) Marshal.FreeHGlobal(padding);
            Marshal.FreeHGlobal(algorithm);
        }
    }

    private static byte[] Export(IntPtr key, string blobType)
    {
        Check(NCryptExportKey(key, IntPtr.Zero, blobType, IntPtr.Zero, null, 0, out int required, 0), "size public key export");
        byte[] output = new byte[required];
        Check(NCryptExportKey(key, IntPtr.Zero, blobType, IntPtr.Zero, output, output.Length, out int written, 0), "public key export");
        return written == output.Length ? output : output[..written];
    }

    private static void SetIntProperty(IntPtr key, string name, int value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        Check(NCryptSetProperty(key, name, bytes, bytes.Length, 0), $"set {name}");
    }

    private static void Check(int status, string operation)
    {
        if (status != Success) throw new InvalidOperationException($"Unable to {operation} (NCrypt 0x{status:X8}).");
    }

    private static void TryDeletePartialKey(IntPtr provider, string keyName, ref IntPtr key)
    {
        try
        {
            if (key == IntPtr.Zero)
                _ = NCryptOpenKey(provider, out key, keyName, 0, 0);
            if (key != IntPtr.Zero)
            {
                if (NCryptDeleteKey(key, 0) == Success)
                    key = IntPtr.Zero;
            }
        }
        catch
        {
            // Preserve the original TPM error. A later creation attempt uses the same
            // namespaced key name and can recover or report the residual key safely.
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OaepPaddingInfo { public IntPtr pszAlgId; public IntPtr pbLabel; public int cbLabel; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TpmDeviceInfo
    {
        public uint structVersion;
        public uint tpmVersion;
        public uint tpmInterfaceType;
        public uint tpmImpRevision;
    }

    [DllImport("tbs.dll")]
    private static extern uint Tbsi_GetDeviceInfo(uint size, ref TpmDeviceInfo info);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptDeleteKey(IntPtr hKey, int flags);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[]? pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[]? pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList, byte[]? pbOutput, int cbOutput, out int pcbResult, int dwFlags);
}

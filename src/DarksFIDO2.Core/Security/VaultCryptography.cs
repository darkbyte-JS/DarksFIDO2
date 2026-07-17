using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DarksFIDO2.Core.Security;

public static class VaultCryptography
{
    private static readonly byte[] LegacyVaultAad = Encoding.UTF8.GetBytes("DarksFIDO2:vault:v1");

    public static byte[] GenerateMasterKey() => RandomNumberGenerator.GetBytes(32);
    public static byte[] GenerateKeyfile() => RandomNumberGenerator.GetBytes(64);

    public static string GenerateRecoveryCode()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(20);
        string raw = Convert.ToHexString(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return string.Join('-', Enumerable.Range(0, 5).Select(i => raw.Substring(i * 8, 8)));
    }

    public static byte[] DeriveFactorKey(string pin, byte[] salt, int iterations, byte[]? keyfile)
    {
        if (string.IsNullOrWhiteSpace(pin) || pin.Length is < 6 or > 1_024)
            throw new ArgumentException("PIN/passphrase must contain at least 6 characters.", nameof(pin));
        if (salt is null || salt.Length != 32) throw new ArgumentException("The key-derivation salt is invalid.", nameof(salt));
        if (iterations is < DataValidation.MinimumPbkdf2Iterations or > DataValidation.MaximumPbkdf2Iterations)
            throw new ArgumentOutOfRangeException(nameof(iterations), "The key-derivation work factor is outside the supported safety range.");
        if (keyfile is { Length: > 1024 * 1024 }) throw new ArgumentException("The keyfile exceeds the 1 MiB safety limit.", nameof(keyfile));

        byte[] pinKey = Rfc2898DeriveBytes.Pbkdf2(pin, salt, iterations, HashAlgorithmName.SHA256, 32);
        if (keyfile is null) return pinKey;

        byte[] keyfileHash = SHA256.HashData(keyfile);
        byte[] combined = Hkdf(pinKey, keyfileHash, "DarksFIDO2:pin+keyfile", 32);
        CryptographicOperations.ZeroMemory(pinKey);
        CryptographicOperations.ZeroMemory(keyfileHash);
        return combined;
    }

    public static byte[] ComputeKeyfileHash(byte[] keyfile) => SHA256.HashData(keyfile);

    public static byte[] WrapMasterKey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> factorKey, Guid profileId)
    {
        if (masterKey.Length != 32 || factorKey.Length != 32 || profileId == Guid.Empty)
            throw new ArgumentException("Invalid profile key material.");
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[masterKey.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(factorKey, 16);
        aes.Encrypt(nonce, masterKey, ciphertext, tag, profileId.ToByteArray());
        return JsonSerializer.SerializeToUtf8Bytes(new WrappedSecret { Nonce = nonce, Ciphertext = ciphertext, Tag = tag });
    }

    public static byte[] UnwrapMasterKey(ReadOnlySpan<byte> wrappedBytes, ReadOnlySpan<byte> factorKey, Guid profileId)
    {
        if (wrappedBytes.Length is < 1 or > 256 * 1024 || factorKey.Length != 32 || profileId == Guid.Empty)
            throw new CryptographicException("The profile key envelope is invalid.");
        WrappedSecret wrapped = JsonSerializer.Deserialize<WrappedSecret>(wrappedBytes)
            ?? throw new CryptographicException("The profile key envelope is invalid.");
        if (wrapped.Nonce.Length != 12 || wrapped.Tag.Length != 16 || wrapped.Ciphertext.Length != 32)
            throw new CryptographicException("The profile key envelope is invalid.");
        byte[] master = new byte[wrapped.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(factorKey, 16);
            aes.Decrypt(wrapped.Nonce, wrapped.Ciphertext, wrapped.Tag, master, profileId.ToByteArray());
            return master;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(master);
            throw new CryptographicException("The PIN or keyfile is incorrect, or the profile was tampered with.");
        }
    }

    public static byte[] EncryptVault(VaultData data, ReadOnlySpan<byte> masterKey)
    {
        if (masterKey.Length != 32) throw new ArgumentException("The vault master key is invalid.", nameof(masterKey));
        DataValidation.Vault(data);
        const string magic = "DFV2";
        byte[] profileSalt = data.ProfileId.ToByteArray();
        byte[] vaultAad = BuildVaultAad(magic, data.ProfileId);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(data, JsonOptions);
        if (plaintext.Length > DataValidation.MaximumPlaintextVaultBytes)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("The vault exceeds the supported size limit.");
        }
        byte[] encKey = Hkdf(masterKey, profileSalt, "DarksFIDO2:vault:encryption", 32);
        byte[] macKey = Hkdf(masterKey, profileSalt, "DarksFIDO2:vault:integrity", 32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        try
        {
            using (var aes = new AesGcm(encKey, 16))
                aes.Encrypt(nonce, plaintext, ciphertext, tag, vaultAad);

            byte[] macInput = Combine(vaultAad, nonce, ciphertext, tag);
            byte[] hmac = HMACSHA256.HashData(macKey, macInput);
            CryptographicOperations.ZeroMemory(macInput);
            return JsonSerializer.SerializeToUtf8Bytes(new VaultEnvelope
            {
                Magic = magic,
                Nonce = nonce,
                Ciphertext = ciphertext,
                Tag = tag,
                Hmac = hmac
            }, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
            CryptographicOperations.ZeroMemory(profileSalt);
        }
    }

    public static VaultData DecryptVault(ReadOnlySpan<byte> envelopeBytes, ReadOnlySpan<byte> masterKey, Guid profileId)
    {
        if (envelopeBytes.Length is < 1 or > DataValidation.MaximumProtectedFileBytes ||
            masterKey.Length != 32 || profileId == Guid.Empty)
            throw new CryptographicException("The vault envelope is invalid.");
        VaultEnvelope envelope = JsonSerializer.Deserialize<VaultEnvelope>(envelopeBytes, JsonOptions)
            ?? throw new CryptographicException("The vault envelope is invalid.");
        if (envelope.Magic is null || envelope.Magic.Length is < 1 or > 16 ||
            envelope.Nonce.Length != 12 || envelope.Tag.Length != 16 || envelope.Hmac.Length != 32 ||
            envelope.Ciphertext.Length is < 1 or > DataValidation.MaximumPlaintextVaultBytes)
            throw new CryptographicException("The vault envelope has invalid field lengths.");

        bool legacy = string.Equals(envelope.Magic, "DFV1", StringComparison.Ordinal);
        byte[] profileSalt = legacy ? [] : profileId.ToByteArray();
        byte[] vaultAad = legacy ? LegacyVaultAad : BuildVaultAad(envelope.Magic, profileId);
        byte[] encKey = Hkdf(masterKey, profileSalt, "DarksFIDO2:vault:encryption", 32);
        byte[] macKey = Hkdf(masterKey, profileSalt, "DarksFIDO2:vault:integrity", 32);
        byte[] macInput = Combine(vaultAad, envelope.Nonce, envelope.Ciphertext, envelope.Tag);
        byte[] expected = HMACSHA256.HashData(macKey, macInput);
        CryptographicOperations.ZeroMemory(macInput);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, envelope.Hmac))
                throw new CryptographicException("Vault integrity verification failed. The file may have been tampered with.");
            if (envelope.Magic is not ("DFV1" or "DFV2"))
                throw new CryptographicException("Unsupported vault format.");

            byte[] plaintext = new byte[envelope.Ciphertext.Length];
            try
            {
                using (var aes = new AesGcm(encKey, 16))
                    aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, vaultAad);
                VaultData data = JsonSerializer.Deserialize<VaultData>(plaintext, JsonOptions)
                    ?? throw new CryptographicException("The decrypted vault is invalid.");
                DataValidation.Vault(data, profileId);
                return data;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
            CryptographicOperations.ZeroMemory(expected);
            if (profileSalt.Length > 0) CryptographicOperations.ZeroMemory(profileSalt);
        }
    }

    public static byte[] Hkdf(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        if (ikm.IsEmpty || ikm.Length > 1024 * 1024) throw new ArgumentException("HKDF input key material has an invalid length.", nameof(ikm));
        if (salt.Length > 1024 * 1024) throw new ArgumentException("HKDF salt is too large.", nameof(salt));
        if (info is null || info.Length > 1_024) throw new ArgumentException("HKDF context is invalid.", nameof(info));
        if (length is < 1 or > 255 * 32) throw new ArgumentOutOfRangeException(nameof(length));
        byte[] actualSalt = salt.IsEmpty ? new byte[32] : salt.ToArray();
        byte[] prk = HMACSHA256.HashData(actualSalt, ikm);
        byte[] infoBytes = Encoding.UTF8.GetBytes(info);
        byte[] output = new byte[length];
        byte[] previous = [];
        int offset = 0;
        byte counter = 1;
        try
        {
            while (offset < length)
            {
                byte[] input = Combine(previous, infoBytes, new byte[] { counter });
                byte[] block = HMACSHA256.HashData(prk, input);
                CryptographicOperations.ZeroMemory(input);
                if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
                previous = block;
                int take = Math.Min(block.Length, length - offset);
                block.AsSpan(0, take).CopyTo(output.AsSpan(offset));
                offset += take;
                counter++;
            }
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualSalt);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(infoBytes);
            if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
        }
    }

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        MaxDepth = 64
    };

    private static byte[] Combine(params ReadOnlyMemory<byte>[] parts)
    {
        byte[] result = new byte[parts.Sum(x => x.Length)];
        int offset = 0;
        foreach (ReadOnlyMemory<byte> part in parts)
        {
            part.Span.CopyTo(result.AsSpan(offset));
            offset += part.Length;
        }
        return result;
    }

    private static byte[] BuildVaultAad(string magic, Guid profileId) =>
        Encoding.UTF8.GetBytes($"DarksFIDO2:vault:{magic}:{profileId:D}");
}

public static class DpapiProtector
{
    private static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("DarksFIDO2:DPAPI:v1"));
    private const int CryptprotectUiForbidden = 0x1;

    public static byte[] Protect(ReadOnlySpan<byte> plaintext) => Transform(plaintext, protect: true);
    public static byte[] Unprotect(ReadOnlySpan<byte> ciphertext) => Transform(ciphertext, protect: false);

    private static byte[] Transform(ReadOnlySpan<byte> input, bool protect)
    {
        if (input.IsEmpty || input.Length > DataValidation.MaximumProtectedFileBytes)
            throw new CryptographicException("The DPAPI input has an invalid length.");
        byte[] inputArray = input.ToArray();
        GCHandle inputHandle = default;
        GCHandle entropyHandle = default;
        DataBlob output = default;
        try
        {
            inputHandle = GCHandle.Alloc(inputArray, GCHandleType.Pinned);
            entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
            var inputBlob = new DataBlob { cbData = inputArray.Length, pbData = inputHandle.AddrOfPinnedObject() };
            var entropyBlob = new DataBlob { cbData = Entropy.Length, pbData = entropyHandle.AddrOfPinnedObject() };
            bool ok = protect
                ? CryptProtectData(ref inputBlob, "Darks FIDO2 protected data", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptprotectUiForbidden, out output)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptprotectUiForbidden, out output);
            if (!ok) throw new CryptographicException(Marshal.GetLastWin32Error());
            if (output.cbData <= 0 || output.cbData > DataValidation.MaximumProtectedFileBytes)
                throw new CryptographicException("DPAPI returned an invalid output length.");
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, result.Length);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputArray);
            if (inputHandle.IsAllocated) inputHandle.Free();
            if (entropyHandle.IsAllocated) entropyHandle.Free();
            if (output.pbData != IntPtr.Zero) LocalFree(output.pbData);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob pDataIn, string? szDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DataBlob pDataIn, IntPtr ppszDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);
}

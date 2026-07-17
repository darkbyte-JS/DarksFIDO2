using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarksFIDO2.Core.Security;

namespace DarksFIDO2.Core;

public sealed class VaultBackupService
{
    private const int BackupIterations = 700_000;
    private static readonly byte[] BackupAad = Encoding.UTF8.GetBytes("DarksFIDO2:backup:v1");

    private sealed class BackupEnvelope
    {
        public string Magic { get; set; } = "DFB1";
        public byte[] Salt { get; set; } = [];
        public int Iterations { get; set; } = 700_000;
        public byte[] Nonce { get; set; } = [];
        public byte[] Ciphertext { get; set; } = [];
        public byte[] Tag { get; set; } = [];
    }

    public void Export(VaultData data, string password, string path)
    {
        if (password.Length is < 10 or > 1_024) throw new ArgumentException("Backup password must contain 10 to 1,024 characters.");
        DataValidation.Vault(data);
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, BackupIterations, HashAlgorithmName.SHA256, 32);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(data, VaultCryptography.JsonOptions);
        if (plaintext.Length > DataValidation.MaximumPlaintextVaultBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("The vault exceeds the supported backup size limit.");
        }
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, BackupAad);
            byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(new BackupEnvelope
            {
                Salt = salt, Nonce = nonce, Ciphertext = ciphertext, Tag = tag
            }, VaultCryptography.JsonOptions);
            try { SecureFile.AtomicWrite(path, serialized); }
            finally { CryptographicOperations.ZeroMemory(serialized); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public VaultData Import(string path, string password)
    {
        if (password.Length is < 1 or > 1_024) throw new ArgumentException("The backup password has an invalid length.", nameof(password));
        byte[] serialized = SecureFile.ReadAllBytes(path, DataValidation.MaximumProtectedFileBytes);
        BackupEnvelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<BackupEnvelope>(serialized, VaultCryptography.JsonOptions)
                ?? throw new CryptographicException("Invalid backup file.");
        }
        catch (JsonException ex) { throw new CryptographicException("Invalid backup file.", ex); }
        finally { CryptographicOperations.ZeroMemory(serialized); }
        if (envelope.Iterations != BackupIterations || envelope.Salt.Length != 32 || envelope.Nonce.Length != 12 ||
            envelope.Tag.Length != 16 || envelope.Ciphertext.Length is < 1 or > DataValidation.MaximumPlaintextVaultBytes)
            throw new CryptographicException("The backup envelope has invalid security parameters.");
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, envelope.Salt, envelope.Iterations, HashAlgorithmName.SHA256, 32);
        byte[] plaintext = new byte[envelope.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, BackupAad);
            if (envelope.Magic != "DFB1") throw new CryptographicException("Unsupported backup format.");
            VaultData data = JsonSerializer.Deserialize<VaultData>(plaintext, VaultCryptography.JsonOptions)
                ?? throw new CryptographicException("Invalid decrypted backup.");
            DataValidation.Vault(data);
            return data;
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("The backup password is wrong or the file was tampered with.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

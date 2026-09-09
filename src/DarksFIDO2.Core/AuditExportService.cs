using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarksFIDO2.Core.Security;

namespace DarksFIDO2.Core;

public sealed class AuditExportService
{
    public SignedAuditExport ExportSignedCsv(VaultData vault, string outputPath)
    {
        EnsureSigningKey(vault);
        string csvPath = Path.ChangeExtension(outputPath, ".csv");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(csvPath))!);
        var csv = new StringBuilder("Timestamp (UTC),Type,Outcome,Message\r\n");
        foreach (AuditEvent item in vault.AuditLog.OrderBy(x => x.TimestampUtc))
            csv.Append(Csv(item.TimestampUtc.ToString("O"))).Append(',').Append(Csv(item.Type)).Append(',')
               .Append(Csv(item.Outcome)).Append(',').Append(Csv(item.Message)).Append("\r\n");
        byte[] content = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true).GetBytes(csv.ToString());
        SecureFile.AtomicWrite(csvPath, content);

        byte[] signature;
        using (ECDsa signer = ECDsa.Create())
        {
            signer.ImportPkcs8PrivateKey(vault.AuditSigningPrivateKeyPkcs8!, out _);
            signature = signer.SignData(content, HashAlgorithmName.SHA256);
        }
        string signaturePath = csvPath + ".sig";
        string publicKeyPath = csvPath + ".public.pem";
        byte[] signatureDocument = JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = "DarksFIDO2-Audit-Signature-v1",
            algorithm = "ECDSA-P256-SHA256",
            file = Path.GetFileName(csvPath),
            signature = Convert.ToBase64String(signature)
        }, new JsonSerializerOptions { WriteIndented = true });
        byte[] publicDocument = new UTF8Encoding(false).GetBytes(PemEncoding.WriteString("PUBLIC KEY", vault.AuditSigningPublicKeySpki!));
        SecureFile.AtomicWrite(signaturePath, signatureDocument);
        SecureFile.AtomicWrite(publicKeyPath, publicDocument);
        CryptographicOperations.ZeroMemory(content);
        CryptographicOperations.ZeroMemory(signature);
        CryptographicOperations.ZeroMemory(signatureDocument);
        CryptographicOperations.ZeroMemory(publicDocument);
        return new SignedAuditExport(csvPath, signaturePath, publicKeyPath);
    }

    public bool Verify(string csvPath, string signaturePath, string publicKeyPath)
    {
        byte[] data = SecureFile.ReadAllBytes(csvPath, DataValidation.MaximumProtectedFileBytes);
        byte[] signatureBytes = SecureFile.ReadAllBytes(signaturePath, 64 * 1024);
        byte[] publicBytes = SecureFile.ReadAllBytes(publicKeyPath, 64 * 1024);
        try
        {
            using JsonDocument document = JsonDocument.Parse(signatureBytes, new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = document.RootElement;
            if (root.GetProperty("format").GetString() != "DarksFIDO2-Audit-Signature-v1" ||
                root.GetProperty("algorithm").GetString() != "ECDSA-P256-SHA256" ||
                root.GetProperty("file").GetString() != Path.GetFileName(csvPath)) return false;
            byte[] signature = Convert.FromBase64String(root.GetProperty("signature").GetString() ?? "");
            try
            {
                if (signature.Length is < 8 or > 1024) return false;
                using ECDsa verifier = ECDsa.Create();
                verifier.ImportFromPem(Encoding.UTF8.GetString(publicBytes));
                return verifier.KeySize == 256 && verifier.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or KeyNotFoundException) { return false; }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            CryptographicOperations.ZeroMemory(signatureBytes);
            CryptographicOperations.ZeroMemory(publicBytes);
        }
    }

    private static void EnsureSigningKey(VaultData vault)
    {
        if (vault.AuditSigningPrivateKeyPkcs8 is not null && vault.AuditSigningPublicKeySpki is not null)
        {
            byte[] challenge = SHA256.HashData(Encoding.UTF8.GetBytes("DarksFIDO2:audit-key-validation:v1"));
            byte[] signature = [];
            try
            {
                using ECDsa existingSigner = ECDsa.Create();
                existingSigner.ImportPkcs8PrivateKey(vault.AuditSigningPrivateKeyPkcs8, out int privateRead);
                using ECDsa verifier = ECDsa.Create();
                verifier.ImportSubjectPublicKeyInfo(vault.AuditSigningPublicKeySpki, out int publicRead);
                if (privateRead != vault.AuditSigningPrivateKeyPkcs8.Length || publicRead != vault.AuditSigningPublicKeySpki.Length || existingSigner.KeySize != 256 || verifier.KeySize != 256)
                    throw new CryptographicException("The audit signing key pair is invalid.");
                signature = existingSigner.SignHash(challenge);
                if (!verifier.VerifyHash(challenge, signature)) throw new CryptographicException("The audit signing key pair does not match.");
                return;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(challenge);
                if (signature.Length > 0) CryptographicOperations.ZeroMemory(signature);
            }
        }
        using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        vault.AuditSigningPrivateKeyPkcs8 = signer.ExportPkcs8PrivateKey();
        vault.AuditSigningPublicKeySpki = signer.ExportSubjectPublicKeyInfo();
    }

    private static string Csv(string value)
    {
        string safe = value;
        int first = 0;
        while (first < safe.Length && safe[first] is ' ' or '\t') first++;
        if (first < safe.Length && safe[first] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n') safe = "'" + safe;
        return '"' + safe.Replace("\"", "\"\"") + '"';
    }
}

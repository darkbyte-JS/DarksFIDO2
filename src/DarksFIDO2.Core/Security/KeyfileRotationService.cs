using System.Security.Cryptography;

namespace DarksFIDO2.Core.Security;

public static class KeyfileRotationService
{
    private const int MaximumKeyfileBytes = 1024 * 1024;

    public static void WriteThenCommit(string path, ReadOnlySpan<byte> newKeyfile, Action commitVaultPolicy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(commitVaultPolicy);
        if (newKeyfile.IsEmpty || newKeyfile.Length > MaximumKeyfileBytes)
            throw new ArgumentException("The replacement keyfile has an invalid size.", nameof(newKeyfile));

        string fullPath = Path.GetFullPath(path);
        byte[]? previous = File.Exists(fullPath) ? SecureFile.ReadAllBytes(fullPath, MaximumKeyfileBytes) : null;
        bool committed = false;
        try
        {
            SecureFile.AtomicWrite(fullPath, newKeyfile);
            byte[] verification = SecureFile.ReadAllBytes(fullPath, MaximumKeyfileBytes);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(verification, newKeyfile))
                    throw new IOException("The replacement keyfile could not be verified after writing.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(verification);
            }

            commitVaultPolicy();
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                try
                {
                    if (previous is null) File.Delete(fullPath);
                    else SecureFile.AtomicWrite(fullPath, previous);
                }
                catch
                {
                    // The old vault policy remains active. Preserve the original exception;
                    // the UI also keeps the current keyfile path selected for recovery.
                }
            }
            if (previous is not null) CryptographicOperations.ZeroMemory(previous);
        }
    }
}

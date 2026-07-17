using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using DarksFIDO2.Core.Security;

namespace DarksFIDO2.Core.Passkeys;

public sealed class PasskeyProviderContext
{
    private static readonly TimeSpan MaximumAge = TimeSpan.FromMinutes(2);
    private const int MaximumContextBytes = 64 * 1024;
    private readonly string _contextPath;

    public PasskeyProviderContext(string? root = null)
    {
        root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DarksFIDO2", "PasskeyProvider");
        Directory.CreateDirectory(root);
        _contextPath = Path.Combine(root, "active-profile.dpapi");
    }

    public void SetActiveProfile(Guid profileId)
    {
        var context = new ActiveProfileContext(profileId, Environment.ProcessId, DateTimeOffset.UtcNow);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(context, VaultCryptography.JsonOptions);
        byte[] protectedBytes = DpapiProtector.Protect(plaintext);
        try
        {
            SecureFile.AtomicWrite(_contextPath, protectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public Guid? GetActiveProfileId()
    {
        try
        {
            ActiveProfileContext? context = ReadContext();
            if (context is null || context.ProfileId == Guid.Empty || context.OwnerProcessId <= 0) return null;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (context.UpdatedUtc > now.AddMinutes(1) || now - context.UpdatedUtc > MaximumAge) return null;
            using Process process = Process.GetProcessById(context.OwnerProcessId);
            if (process.HasExited || process.StartTime.ToUniversalTime() > context.UpdatedUtc.UtcDateTime) return null;
            return context.ProfileId;
        }
        catch { return null; }
    }

    public void Clear(Guid? expectedProfileId = null)
    {
        ActiveProfileContext? context = null;
        try { context = ReadContext(); } catch { }
        if (expectedProfileId is Guid expected && context is not null && context.ProfileId != expected) return;
        try { File.Delete(_contextPath); } catch { }
    }

    private ActiveProfileContext? ReadContext()
    {
        if (!File.Exists(_contextPath)) return null;
        byte[] protectedBytes = SecureFile.ReadAllBytes(_contextPath, MaximumContextBytes);
        byte[] plaintext = DpapiProtector.Unprotect(protectedBytes);
        try { return JsonSerializer.Deserialize<ActiveProfileContext>(plaintext, VaultCryptography.JsonOptions); }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private sealed record ActiveProfileContext(Guid ProfileId, int OwnerProcessId, DateTimeOffset UpdatedUtc);
}

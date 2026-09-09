using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Diagnostics;

namespace DarksFIDO2.Core;

public sealed class CliRequest
{
    public string Command { get; set; } = "";
    public string? OutputPath { get; set; }
}

public sealed class CliResponse
{
    public bool Success { get; set; }
    public object? Data { get; set; }
    public string? Error { get; set; }
}

public static class CliBridge
{
    private const int MaximumRequestCharacters = 64 * 1024;
    private const int MaximumResponseCharacters = 1024 * 1024;

    public static string PipeName
    {
        get
        {
            string identity;
            try { identity = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName; }
            catch { identity = Environment.UserName; }
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(identity.ToUpperInvariant()));
            return "DarksFIDO2-" + Convert.ToHexString(hash.AsSpan(0, 8));
        }
    }

    public static async Task<CliResponse> SendAsync(CliRequest request, int timeoutMilliseconds = 3000)
    {
        using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = new CancellationTokenSource(timeoutMilliseconds);
        await client.ConnectAsync(timeout.Token).ConfigureAwait(false);
        using var writer = new StreamWriter(client, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(client, Encoding.UTF8, leaveOpen: true);
        string serialized = JsonSerializer.Serialize(request);
        if (serialized.Length > MaximumRequestCharacters) throw new InvalidDataException("The CLI request is too large.");
        await writer.WriteLineAsync(serialized).ConfigureAwait(false);
        string? line = await ReadLineBoundedAsync(reader, MaximumResponseCharacters, timeout.Token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<CliResponse>(line ?? "") ?? new CliResponse { Error = "Invalid response from the GUI.", Success = false };
    }

    internal static async Task<string?> ReadLineBoundedAsync(StreamReader reader, int maximumCharacters, CancellationToken cancellationToken)
    {
        var value = new StringBuilder(Math.Min(maximumCharacters, 4096));
        char[] buffer = new char[1];
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) return value.Length == 0 ? null : value.ToString();
            if (buffer[0] == '\n') return value.ToString();
            if (buffer[0] == '\r') continue;
            if (value.Length >= maximumCharacters) throw new InvalidDataException("The CLI message exceeds the safety limit.");
            value.Append(buffer[0]);
        }
    }
}

public sealed class CliBridgeServer : IAsyncDisposable
{
    private readonly Func<UnlockedProfile?> _profileProvider;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public CliBridgeServer(Func<UnlockedProfile?> profileProvider)
    {
        _profileProvider = profileProvider;
    }

    public void Start() => _loop ??= Task.Run(() => AcceptLoop(_cts.Token));

    private async Task AcceptLoop(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeServerStream(CliBridge.PipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
                string? line = await CliBridge.ReadLineBoundedAsync(reader, 64 * 1024, cancellationToken).ConfigureAwait(false);
                CliRequest? request = JsonSerializer.Deserialize<CliRequest>(line ?? "");
                CliResponse response = Handle(request);
                string serialized = JsonSerializer.Serialize(response);
                if (serialized.Length > 1024 * 1024) serialized = JsonSerializer.Serialize(new CliResponse { Success = false, Error = "The CLI response exceeds the safety limit." });
                await writer.WriteLineAsync(serialized).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
            {
                Trace.TraceWarning("Darks FIDO2 CLI bridge rejected a request ({0}).", ex.GetType().Name);
            }
            catch (Exception ex)
            {
                Trace.TraceError("Darks FIDO2 CLI bridge listener failed ({0}).", ex.GetType().Name);
                try { await Task.Delay(250, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            }
        }
    }

    private CliResponse Handle(CliRequest? request)
    {
        if (request is null) return new CliResponse { Success = false, Error = "Invalid request." };
        UnlockedProfile? profile = _profileProvider();
        if (request.Command.Equals("vault-status", StringComparison.OrdinalIgnoreCase))
        {
            return new CliResponse
            {
                Success = true,
                Data = new
                {
                    state = profile is null ? "Locked" : "Unlocked",
                    profile = profile?.Data.ProfileName,
                    protection = profile?.Metadata.DeviceProtection.ToString(),
                    lastAuditEventUtc = profile?.Data.AuditLog.LastOrDefault()?.TimestampUtc
                }
            };
        }
        if (profile is null) return new CliResponse { Success = false, Error = "The GUI profile is locked. Unlock it before using the CLI." };

        return request.Command.ToLowerInvariant() switch
        {
            "list-keys" => new CliResponse
            {
                Success = true,
                Data = new
                {
                    total = profile.Data.FidoKeys.Count,
                    truncated = profile.Data.FidoKeys.Count > 1_000,
                    keys = profile.Data.FidoKeys.Take(1_000).Select(x => new { x.Name, x.Type, x.Transport, x.LastUsedUtc, x.LastVerifiedUtc }).ToArray()
                }
            },
            "check-backups" => new CliResponse
            {
                Success = true,
                Data = new
                {
                    registeredKeys = profile.Data.FidoKeys.Count,
                    backupPresent = profile.Data.FidoKeys.Count >= 2,
                    message = profile.Data.FidoKeys.Count >= 2 ? "At least two keys are registered." : "Register a second FIDO2 key as a backup."
                }
            },
            "export-audit" => new CliResponse { Success = false, Error = "Audit export is GUI-only so another process cannot cause writes through the unlocked app." },
            _ => new CliResponse { Success = false, Error = "Unknown command." }
        };
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loop is not null) try { await _loop.ConfigureAwait(false); } catch (OperationCanceledException) { }
        _cts.Dispose();
    }
}

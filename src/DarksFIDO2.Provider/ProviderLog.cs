using System.Text;

namespace DarksFIDO2.Provider;

internal static class ProviderLog
{
    private const int MaximumWritesPerWindow = 120;
    private const long WindowMilliseconds = 60_000;
    private static readonly object Gate = new();
    private static readonly string DirectoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DarksFIDO2", "PasskeyProvider");
    internal static readonly string FilePath = Path.Combine(DirectoryPath, "provider.log");
    private static long _windowStarted = Environment.TickCount64;
    private static int _windowWrites;
    private static int _suppressedWrites;

    internal static void Write(Guid transactionId, string operation, string message)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(DirectoryPath);
                long now = Environment.TickCount64;
                if (now - _windowStarted >= WindowMilliseconds || now < _windowStarted)
                {
                    if (_suppressedWrites > 0)
                        Append(Guid.Empty, "RateLimit", $"Suppressed {_suppressedWrites} provider log entries during the previous minute.");
                    _windowStarted = now;
                    _windowWrites = 0;
                    _suppressedWrites = 0;
                }
                if (_windowWrites >= MaximumWritesPerWindow)
                {
                    if (_suppressedWrites < int.MaxValue) _suppressedWrites++;
                    return;
                }
                _windowWrites++;
                string safe = new(message.Take(2_048).Select(c => char.IsControl(c) ? ' ' : c).ToArray());
                Append(transactionId, operation, safe);
            }
        }
        catch { }
    }

    private static void Append(Guid transactionId, string operation, string message)
    {
        if (File.Exists(FilePath) && new FileInfo(FilePath).Length > 512 * 1024)
            File.Move(FilePath, FilePath + ".previous", true);
        File.AppendAllText(FilePath, $"{DateTimeOffset.UtcNow:O}\t{transactionId:D}\t{operation}\t{message}{Environment.NewLine}", new UTF8Encoding(false));
    }
}

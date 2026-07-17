using System.Text.Json;
using DarksFIDO2.Core;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    if (args.Length == 0 || args[0] is "--help" or "-h" or "help")
    {
        Help();
        return 0;
    }

    string command = args[0].ToLowerInvariant();
    if (command is not ("list-keys" or "vault-status" or "check-backups"))
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Help();
        return 2;
    }

    try
    {
        CliResponse response = await CliBridge.SendAsync(new CliRequest { Command = command });
        if (!response.Success)
        {
            Console.Error.WriteLine(response.Error);
            return 1;
        }
        Console.WriteLine(JsonSerializer.Serialize(response.Data, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
    catch (TimeoutException)
    {
        Console.Error.WriteLine("Darks FIDO2 is not running or did not respond.");
        return 1;
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("Darks FIDO2 is not running or did not respond.");
        return 1;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static void Help()
{
    Console.WriteLine("""
    darksfido-cli — authorized, read-only companion for Darks FIDO2

    Usage:
      darksfido-cli list-keys
      darksfido-cli vault-status
      darksfido-cli check-backups
    The GUI must be running. Inventory commands require an already-unlocked
    profile. This tool never accepts or prints PINs, keyfiles, TOTP seeds,
    private keys, or other secrets.
    """);
}

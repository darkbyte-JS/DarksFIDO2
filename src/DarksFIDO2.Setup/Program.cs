using System.IO.Compression;
using System.IO;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace DarksFIDO2.Setup;

internal static class Program
{
    private const string AppName = "Darks FIDO2";
    private static readonly string InstallDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DarksFIDO2");
    private static readonly string LegacyInstallDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "DarksFIDO2");
    private static readonly string StartMenuDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "Darks FIDO2");
    private static readonly string DesktopShortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Darks FIDO2.lnk");

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--uninstall-silent", StringComparer.OrdinalIgnoreCase)) return Uninstall(silent: true);
            if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase)) return Uninstall(silent: false);
            return Install(args.Contains("--install-silent", StringComparer.OrdinalIgnoreCase));
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show("Setup stopped safely:\n\n" + ex.Message, "Darks FIDO2 Setup", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            return 1;
        }
    }

    private static int Install(bool silent)
    {
        if (!silent && System.Windows.MessageBox.Show("Install Darks FIDO2 and its Windows virtual passkey provider?\n\nSetup never adds certificates to a trusted store. Windows will install the provider only when its existing signature chain is already trusted.", "Darks FIDO2 Setup", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes)
            return 2;

        using Stream payload = typeof(Program).Assembly.GetManifestResourceStream("DarksFIDO2.Payload.zip")
            ?? throw new InvalidOperationException("The portable application payload is missing from this setup file.");
        string staging = Path.Combine(Path.GetTempPath(), "DarksFIDO2-Setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        try
        {
            string archive = Path.Combine(staging, "payload.zip");
            using (var output = File.Create(archive)) payload.CopyTo(output);
            string extracted = Path.Combine(staging, "app");
            ValidateArchive(archive, extracted);
            ZipFile.ExtractToDirectory(archive, extracted, overwriteFiles: true);
            VerifyExtractedPayload(extracted);

            StopInstalledProcesses();
            DeleteTreeWithoutFollowingReparsePoints(InstallDirectory);
            Directory.CreateDirectory(InstallDirectory);
            foreach (string directory in Directory.GetDirectories(extracted, "*", SearchOption.AllDirectories))
                Directory.CreateDirectory(Path.Combine(InstallDirectory, Path.GetRelativePath(extracted, directory)));
            foreach (string file in Directory.GetFiles(extracted, "*", SearchOption.AllDirectories))
                File.Copy(file, Path.Combine(InstallDirectory, Path.GetRelativePath(extracted, file)), overwrite: true);
            string portableMarker = Path.Combine(InstallDirectory, "portable.mode");
            if (File.Exists(portableMarker)) File.Delete(portableMarker);

            string uninstallPath = Path.Combine(InstallDirectory, "Uninstall Darks FIDO2.exe");
            File.Copy(Environment.ProcessPath!, uninstallPath, overwrite: true);
            Directory.CreateDirectory(StartMenuDirectory);
            CreateShortcut(Path.Combine(StartMenuDirectory, "Darks FIDO2.lnk"), Path.Combine(InstallDirectory, "DarksFIDO2.exe"), InstallDirectory);
            CreateShortcut(DesktopShortcut, Path.Combine(InstallDirectory, "DarksFIDO2.exe"), InstallDirectory);
            CreateShortcut(Path.Combine(StartMenuDirectory, "Uninstall Darks FIDO2.lnk"), uninstallPath, InstallDirectory, "--uninstall");
            WriteUninstallEntry(uninstallPath);
            InstallProviderPackage(staging);
            DeleteTreeWithoutFollowingReparsePoints(LegacyInstallDirectory);
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
        }
        if (!silent)
        {
            System.Windows.MessageBox.Show("Darks FIDO2 is installed. To use it as a virtual passkey for Google and other sites, enable Darks FIDO2 once in Settings > Accounts > Passkeys > Advanced options.", "Darks FIDO2 Setup", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(InstallDirectory, "DarksFIDO2.exe")) { UseShellExecute = true, WorkingDirectory = InstallDirectory });
        }
        return 0;
    }

    private static void StopInstalledProcesses()
    {
        if (!Directory.Exists(InstallDirectory)) return;
        string installRoot = Path.GetFullPath(InstallDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (string processName in new[] { "DarksFIDO2", "darksfido-cli", "DarksFIDO2.Provider" })
        {
            foreach (System.Diagnostics.Process process in System.Diagnostics.Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    string? executable;
                    try { executable = process.MainModule?.FileName; }
                    catch { continue; }
                    if (string.IsNullOrWhiteSpace(executable) ||
                        !Path.GetFullPath(executable).StartsWith(installRoot, StringComparison.OrdinalIgnoreCase))
                        continue;
                    try
                    {
                        if (process.CloseMainWindow()) process.WaitForExit(5_000);
                        if (!process.HasExited)
                        {
                            process.Kill(entireProcessTree: true);
                            if (!process.WaitForExit(10_000))
                                throw new InvalidOperationException("The running Darks FIDO2 process did not stop.");
                        }
                    }
                    catch (InvalidOperationException) when (process.HasExited) { }
                }
            }
        }
    }

    private static int Uninstall(bool silent)
    {
        if (!silent && System.Windows.MessageBox.Show("Uninstall Darks FIDO2?\n\nEncrypted profiles in LocalAppData\\DarksFIDO2 are preserved so they are not destroyed accidentally.", "Uninstall Darks FIDO2", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            return 2;
        try
        {
            string provider = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "darksfido2-provider.exe");
            if (File.Exists(provider))
            {
                using var removal = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(provider, "--unregister") { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = InstallDirectory });
                removal?.WaitForExit(30_000);
            }
        }
        catch { }
        try { RunPowerShell("Get-AppxPackage -Name 'DarksFIDO2.Provider' | Remove-AppxPackage", 60_000); } catch { }
        try { File.Delete(DesktopShortcut); } catch { }
        try { Directory.Delete(StartMenuDirectory, recursive: true); } catch { }
        try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DarksFIDO2", throwOnMissingSubKey: false); } catch { }
        string self = Environment.ProcessPath!;
        DeleteTreeWithoutFollowingReparsePoints(InstallDirectory, self);
        MoveFileEx(self, null, 4);
        MoveFileEx(InstallDirectory, null, 4);
        if (!silent) System.Windows.MessageBox.Show("Darks FIDO2 was uninstalled. Its encrypted profile data was preserved.", "Uninstall Darks FIDO2", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
        return 0;
    }

    private static void WriteUninstallEntry(string uninstallPath)
    {
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DarksFIDO2", writable: true);
        key.SetValue("DisplayName", AppName);
        key.SetValue("DisplayVersion", "0.6.1");
        key.SetValue("Publisher", "Darks FIDO2 Project");
        key.SetValue("InstallLocation", InstallDirectory);
        key.SetValue("DisplayIcon", Path.Combine(InstallDirectory, "DarksFIDO2.exe"));
        key.SetValue("UninstallString", '"' + uninstallPath + "\" --uninstall");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory, string arguments = "")
    {
        Type type = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows shortcut service is unavailable.");
        dynamic shell = Activator.CreateInstance(type)!;
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workingDirectory;
        shortcut.Arguments = arguments;
        shortcut.Description = "Secure local FIDO2, TPM, and TOTP manager";
        shortcut.Save();
    }

    private static void InstallProviderPackage(string staging)
    {
        string packagePath = Path.Combine(staging, "DarksFIDO2.Provider.msix");
        using (Stream package = typeof(Program).Assembly.GetManifestResourceStream("DarksFIDO2.Provider.msix")
            ?? throw new InvalidOperationException("The virtual passkey provider package is missing."))
        using (FileStream output = File.Create(packagePath)) package.CopyTo(output);
        Version packageVersion = ReadProviderPackageVersion(packagePath);
        string escapedPackage = packagePath.Replace("'", "''");
        RunPowerShell($"$existing=Get-AppxPackage -Name 'DarksFIDO2.Provider'; if (!$existing -or [version]$existing.Version -lt [version]'{packageVersion}') {{ Add-AppxPackage -Path '{escapedPackage}' -ForceApplicationShutdown }}", 120_000);

        string alias = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "darksfido2-provider.exe");
        if (!File.Exists(alias)) throw new InvalidOperationException("Windows did not publish the passkey provider execution alias.");
        using System.Diagnostics.Process registration = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(alias, "--register") { UseShellExecute = false, CreateNoWindow = true })
            ?? throw new InvalidOperationException("Unable to register the virtual passkey provider.");
        if (!registration.WaitForExit(30_000)) { registration.Kill(true); throw new TimeoutException("Virtual passkey registration timed out."); }
        if (registration.ExitCode != 0 && registration.ExitCode != unchecked((int)0x8009000F))
            throw new InvalidOperationException($"Windows rejected virtual passkey registration (0x{registration.ExitCode:X8}).");
    }

    private static Version ReadProviderPackageVersion(string packagePath)
    {
        using ZipArchive archive = ZipFile.OpenRead(packagePath);
        ZipArchiveEntry manifest = archive.GetEntry("AppxManifest.xml")
            ?? throw new InvalidOperationException("The provider package manifest is missing.");
        if (manifest.Length is < 1 or > 1024 * 1024)
            throw new InvalidOperationException("The provider package manifest has an invalid size.");
        using Stream stream = manifest.Open();
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 1024 * 1024
        });
        XDocument document = XDocument.Load(reader, LoadOptions.None);
        XNamespace ns = document.Root?.Name.Namespace
            ?? throw new InvalidOperationException("The provider package manifest is invalid.");
        string? value = document.Root?.Element(ns + "Identity")?.Attribute("Version")?.Value;
        if (!Version.TryParse(value, out Version? version) || version.Major < 0 || version.Minor < 0 ||
            version.Build < 0 || version.Revision < 0)
            throw new InvalidOperationException("The provider package version is invalid.");
        return version;
    }

    private static void RunPowerShell(string command, int timeout)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop';" + command));
        using System.Diagnostics.Process process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}") { UseShellExecute = false, CreateNoWindow = true })
            ?? throw new InvalidOperationException("Unable to start Windows package deployment.");
        if (!process.WaitForExit(timeout)) { process.Kill(true); throw new TimeoutException("Windows package deployment timed out."); }
        if (process.ExitCode != 0) throw new InvalidOperationException("Windows package deployment failed.");
    }

    private static void VerifyExtractedPayload(string root)
    {
        string manifestPath = Path.Combine(root, "integrity.sha256.json");
        if (!File.Exists(manifestPath) || new FileInfo(manifestPath).Length > 1024 * 1024)
            throw new CryptographicException("The signed payload integrity manifest is missing or invalid.");
        byte[] manifestBytes = File.ReadAllBytes(manifestPath);
        ReadOnlySpan<byte> manifestJson = manifestBytes;
        if (manifestJson.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) manifestJson = manifestJson[3..];
        Dictionary<string, string> manifest = JsonSerializer.Deserialize<Dictionary<string, string>>(manifestJson)
            ?? throw new CryptographicException("The signed payload integrity manifest is invalid.");
        if (manifest.Count is < 3 or > 10_000) throw new CryptographicException("The payload manifest contains an invalid number of files.");

        string canonicalRoot = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach ((string relative, string expectedHash) in manifest)
        {
            if (string.IsNullOrWhiteSpace(relative) || relative.Length > 1_024 || expectedHash.Length != 64 ||
                Path.IsPathRooted(relative) || relative.Split('/', '\\').Any(part => part is "" or "." or ".."))
                throw new CryptographicException("The payload manifest contains an unsafe path.");
            string fullPath = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!fullPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(fullPath) || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("The payload is incomplete or contains an unsafe link.");
            byte[] actualHash;
            using (FileStream file = File.OpenRead(fullPath)) actualHash = SHA256.HashData(file);
            byte[] wantedHash = Convert.FromHexString(expectedHash);
            if (!CryptographicOperations.FixedTimeEquals(actualHash, wantedHash))
                throw new CryptographicException("The signed application payload failed integrity verification.");
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(wantedHash);
            expected.Add(Path.GetRelativePath(root, fullPath).Replace('\\', '/'));
        }

        foreach (string file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (!relative.Equals("integrity.sha256.json", StringComparison.OrdinalIgnoreCase) && !expected.Contains(relative))
                throw new CryptographicException("The payload contains an unlisted file.");
        }
    }

    private static void ValidateArchive(string archivePath, string extractionRoot)
    {
        using ZipArchive archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count is < 3 or > 10_000) throw new InvalidDataException("The application payload has an invalid entry count.");
        string canonicalRoot = Path.GetFullPath(extractionRoot) + Path.DirectorySeparatorChar;
        long totalLength = 0;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (entry.FullName.Length > 1_024 || entry.Length > 512L * 1024 * 1024 ||
                entry.Length > 0 && entry.CompressedLength == 0 ||
                entry.CompressedLength > 0 && entry.Length / Math.Max(1, entry.CompressedLength) > 1_000)
                throw new InvalidDataException("The application payload contains an unsafe archive entry.");
            totalLength = checked(totalLength + entry.Length);
            if (totalLength > 1024L * 1024 * 1024) throw new InvalidDataException("The application payload exceeds the extraction safety limit.");
            string fullPath = Path.GetFullPath(Path.Combine(extractionRoot, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
            if (!fullPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase) || !paths.Add(fullPath))
                throw new InvalidDataException("The application payload contains an unsafe or duplicate path.");
        }
    }

    private static void DeleteTreeWithoutFollowingReparsePoints(string root, string? preserveFile = null)
    {
        string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        string expectedRoot = Path.GetFullPath(InstallDirectory).TrimEnd(Path.DirectorySeparatorChar);
        string legacyRoot = Path.GetFullPath(LegacyInstallDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if ((!fullRoot.Equals(expectedRoot, StringComparison.OrdinalIgnoreCase) && !fullRoot.Equals(legacyRoot, StringComparison.OrdinalIgnoreCase)) || !Directory.Exists(fullRoot)) return;
        if ((File.GetAttributes(fullRoot) & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(fullRoot, recursive: false);
            return;
        }
        DeleteContents(fullRoot, preserveFile is null ? null : Path.GetFullPath(preserveFile));
        if (preserveFile is null) Directory.Delete(fullRoot, recursive: false);
    }

    private static void DeleteContents(string directory, string? preserveFile)
    {
        foreach (string entry in Directory.GetFileSystemEntries(directory))
        {
            string full = Path.GetFullPath(entry);
            if (preserveFile is not null && full.Equals(preserveFile, StringComparison.OrdinalIgnoreCase)) continue;
            FileAttributes attributes = File.GetAttributes(full);
            if ((attributes & FileAttributes.Directory) == 0) { try { File.Delete(full); } catch { } continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0) { try { Directory.Delete(full, recursive: false); } catch { } continue; }
            DeleteContents(full, preserveFile);
            try { Directory.Delete(full, recursive: false); } catch { }
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existingFileName, string? newFileName, int flags);
}

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
    private static string InstallDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DarksFIDO2");
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
            bool silent = args.Contains("--install-silent", StringComparer.OrdinalIgnoreCase);
            if (silent)
            {
                bool trustCert = args.Contains("--trust-cert", StringComparer.OrdinalIgnoreCase);
                return PerformInstall(InstallDirectory, createDesktopShortcut: true, createStartMenuShortcut: true, trustCertificate: trustCert, (_, _) => { });
            }

            var app = new System.Windows.Application();
            var window = new SetupWindow(InstallDirectory);
            if (window.ShowDialog() == true && window.LaunchAfterInstall)
            {
                string targetExe = Path.Combine(window.SelectedInstallDirectory, "DarksFIDO2.exe");
                if (File.Exists(targetExe))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(targetExe)
                    {
                        UseShellExecute = true,
                        WorkingDirectory = window.SelectedInstallDirectory
                    });
                }
            }
            return 0;
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show("Setup stopped safely:\n\n" + ex.Message, "Darks FIDO2 Setup", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            return 1;
        }
    }

    internal static int PerformInstall(string targetDirectory, bool createDesktopShortcut, bool createStartMenuShortcut, bool trustCertificate, Action<int, string> reportProgress)
    {
        InstallDirectory = Path.GetFullPath(targetDirectory);

        reportProgress(5, "Verifying installer payload...");
        using Stream payload = typeof(Program).Assembly.GetManifestResourceStream("DarksFIDO2.Payload.zip")
            ?? throw new InvalidOperationException("The portable application payload is missing from this setup file.");
        string staging = Path.Combine(Path.GetTempPath(), "DarksFIDO2-Setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        string? rollbackDirectory = null;
        bool previousInstallExisted = false;
        try
        {
            reportProgress(15, "Extracting application files...");
            string archive = Path.Combine(staging, "payload.zip");
            using (var output = File.Create(archive)) payload.CopyTo(output);
            string extracted = Path.Combine(staging, "app");
            ValidateArchive(archive, extracted);
            ZipFile.ExtractToDirectory(archive, extracted, overwriteFiles: true);

            reportProgress(30, "Checking cryptographic integrity hashes...");
            VerifyExtractedPayload(extracted);

            reportProgress(45, "Stopping existing processes...");
            StopInstalledProcesses();
            previousInstallExisted = Directory.Exists(InstallDirectory);
            if (previousInstallExisted)
            {
                rollbackDirectory = InstallDirectory + ".rollback-" + Guid.NewGuid().ToString("N");
                Directory.Move(InstallDirectory, rollbackDirectory);
            }

            try
            {
                reportProgress(60, "Copying application files...");
                Directory.CreateDirectory(InstallDirectory);
                foreach (string directory in Directory.GetDirectories(extracted, "*", SearchOption.AllDirectories))
                    Directory.CreateDirectory(Path.Combine(InstallDirectory, Path.GetRelativePath(extracted, directory)));
                foreach (string file in Directory.GetFiles(extracted, "*", SearchOption.AllDirectories))
                    File.Copy(file, Path.Combine(InstallDirectory, Path.GetRelativePath(extracted, file)), overwrite: true);
                string portableMarker = Path.Combine(InstallDirectory, "portable.mode");
                if (File.Exists(portableMarker)) File.Delete(portableMarker);

                string uninstallPath = Path.Combine(InstallDirectory, "Uninstall Darks FIDO2.exe");
                File.Copy(Environment.ProcessPath!, uninstallPath, overwrite: true);

                reportProgress(75, "Creating shortcuts and registration entries...");
                if (createStartMenuShortcut)
                {
                    Directory.CreateDirectory(StartMenuDirectory);
                    CreateShortcut(Path.Combine(StartMenuDirectory, "Darks FIDO2.lnk"), Path.Combine(InstallDirectory, "DarksFIDO2.exe"), InstallDirectory);
                    CreateShortcut(Path.Combine(StartMenuDirectory, "Uninstall Darks FIDO2.lnk"), uninstallPath, InstallDirectory, "--uninstall");
                }
                if (createDesktopShortcut)
                {
                    CreateShortcut(DesktopShortcut, Path.Combine(InstallDirectory, "DarksFIDO2.exe"), InstallDirectory);
                }
                WriteUninstallEntry(uninstallPath);

                string? rollbackProviderPackage = rollbackDirectory is null
                    ? null
                    : Path.Combine(rollbackDirectory, "DarksFIDO2.Provider.msix");
                InstallProviderPackage(staging, rollbackProviderPackage, trustCertificate, reportProgress);
                reportProgress(100, "Installation complete!");
            }
            catch
            {
                try { DeleteTreeWithoutFollowingReparsePoints(InstallDirectory); } catch { }
                if (rollbackDirectory is not null && Directory.Exists(rollbackDirectory))
                {
                    Directory.Move(rollbackDirectory, InstallDirectory);
                    RestoreShellIntegration();
                }
                else
                {
                    try { File.Delete(DesktopShortcut); } catch { }
                    try { Directory.Delete(StartMenuDirectory, recursive: true); } catch { }
                    try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DarksFIDO2", throwOnMissingSubKey: false); } catch { }
                }
                throw;
            }

            if (rollbackDirectory is not null)
            {
                try { DeleteTreeWithoutFollowingReparsePoints(rollbackDirectory); } catch { }
                rollbackDirectory = null;
            }
            try { DeleteTreeWithoutFollowingReparsePoints(LegacyInstallDirectory); } catch { }
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
            if (!previousInstallExisted && rollbackDirectory is not null)
            {
                try { DeleteTreeWithoutFollowingReparsePoints(rollbackDirectory); } catch { }
            }
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
        try
        {
            var pm = new Windows.Management.Deployment.PackageManager();
            var target = System.Linq.Enumerable.FirstOrDefault(pm.FindPackagesForUser(string.Empty), p => p.Id.Name == "DarksFIDO2.Provider");
            if (target != null)
            {
                pm.RemovePackageAsync(target.Id.FullName).AsTask().GetAwaiter().GetResult();
            }
        }
        catch { }
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
        string version = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "Unknown";
        try
        {
            string? detected = System.Diagnostics.FileVersionInfo.GetVersionInfo(Path.Combine(InstallDirectory, "DarksFIDO2.exe")).ProductVersion;
            if (Version.TryParse(detected?.Split('+')[0], out Version? parsed)) version = parsed.ToString(3);
        }
        catch { }
        using RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DarksFIDO2", writable: true);
        key.SetValue("DisplayName", AppName);
        key.SetValue("DisplayVersion", version);
        key.SetValue("Publisher", "Darks FIDO2 Project");
        key.SetValue("InstallLocation", InstallDirectory);
        key.SetValue("DisplayIcon", Path.Combine(InstallDirectory, "DarksFIDO2.exe"));
        key.SetValue("UninstallString", '"' + uninstallPath + "\" --uninstall");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void RestoreShellIntegration()
    {
        string executable = Path.Combine(InstallDirectory, "DarksFIDO2.exe");
        string uninstallPath = Path.Combine(InstallDirectory, "Uninstall Darks FIDO2.exe");
        if (!File.Exists(executable) || !File.Exists(uninstallPath)) return;
        Directory.CreateDirectory(StartMenuDirectory);
        CreateShortcut(Path.Combine(StartMenuDirectory, "Darks FIDO2.lnk"), executable, InstallDirectory);
        CreateShortcut(DesktopShortcut, executable, InstallDirectory);
        CreateShortcut(Path.Combine(StartMenuDirectory, "Uninstall Darks FIDO2.lnk"), uninstallPath, InstallDirectory, "--uninstall");
        WriteUninstallEntry(uninstallPath);
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

    private static void EnsureCertificateTrusted(string packagePath, Action<int, string>? reportProgress)
    {
        try
        {
            using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(packagePath);

            // Ensure LocalMachine TrustedPeople
            try
            {
                using var storeLM = new System.Security.Cryptography.X509Certificates.X509Store(
                    System.Security.Cryptography.X509Certificates.StoreName.TrustedPeople,
                    System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                storeLM.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
                var existingLM = storeLM.Certificates.Find(
                    System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                    cert.Thumbprint, false);
                if (existingLM.Count == 0)
                {
                    storeLM.Add(cert);
                    reportProgress?.Invoke(78, "Trusted package certificate in LocalMachine store.");
                }
            }
            catch { }

            // Ensure CurrentUser TrustedPeople
            try
            {
                using var storeCU = new System.Security.Cryptography.X509Certificates.X509Store(
                    System.Security.Cryptography.X509Certificates.StoreName.TrustedPeople,
                    System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                storeCU.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
                var existingCU = storeCU.Certificates.Find(
                    System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                    cert.Thumbprint, false);
                if (existingCU.Count == 0)
                {
                    storeCU.Add(cert);
                }
            }
            catch { }
        }
        catch { }
    }

    private static void InstallProviderPackage(string staging, string? rollbackPackagePath, bool trustCertificate, Action<int, string>? reportProgress = null)
    {
        string packagePath = Path.Combine(staging, "DarksFIDO2.Provider.msix");
        using (Stream package = typeof(Program).Assembly.GetManifestResourceStream("DarksFIDO2.Provider.msix")
            ?? throw new InvalidOperationException("The virtual passkey provider package is missing."))
        using (FileStream output = File.Create(packagePath)) package.CopyTo(output);
        File.Copy(packagePath, Path.Combine(InstallDirectory, "DarksFIDO2.Provider.msix"), overwrite: true);
        Version packageVersion = ReadProviderPackageVersion(packagePath);
        ProviderPackageState? previous = ReadInstalledProviderState();
        bool packageChanged = previous is null || previous.ParsedVersion < packageVersion;
        try
        {
            if (packageChanged || previous is null)
            {
                if (trustCertificate)
                {
                    EnsureCertificateTrusted(packagePath, reportProgress);
                }
                reportProgress?.Invoke(80, "Deploying Windows passkey provider package (0%)...");
                var pm = new Windows.Management.Deployment.PackageManager();
                var op = pm.AddPackageAsync(new Uri(packagePath), null, Windows.Management.Deployment.DeploymentOptions.ForceApplicationShutdown);
                op.Progress = (result, progress) =>
                {
                    int pct = 80 + (int)(progress.percentage * 0.12);
                    reportProgress?.Invoke(pct, $"Deploying Windows passkey provider package ({progress.percentage}%)...");
                };
                var deploymentResult = op.AsTask().GetAwaiter().GetResult();
                if (deploymentResult.IsRegistered == false && deploymentResult.ExtendedErrorCode != null)
                {
                    uint hr = (uint)deploymentResult.ExtendedErrorCode.HResult;
                    if (hr == 0x800B0109)
                    {
                        throw new InvalidOperationException(
                            "Windows package deployment failed (0x800B0109): The package certificate is not trusted by Windows.\n\n" +
                            "If you are testing a development build prior to SignPath certification, please re-run Setup and select 'Register certificate into Trusted People', or import the certificate into the Trusted People store.");
                    }
                    throw new InvalidOperationException($"Windows package deployment failed: {deploymentResult.ErrorText} (0x{hr:X8})");
                }
            }

            reportProgress?.Invoke(95, "Registering virtual passkey execution alias...");
            string alias = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "darksfido2-provider.exe");
            if (!File.Exists(alias)) throw new InvalidOperationException("Windows did not publish the passkey provider execution alias.");
            using System.Diagnostics.Process registration = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(alias, "--register") { UseShellExecute = false, CreateNoWindow = true })
                ?? throw new InvalidOperationException("Unable to register the virtual passkey provider.");
            if (!registration.WaitForExit(30_000)) { registration.Kill(true); throw new TimeoutException("Virtual passkey registration timed out."); }
            if (registration.ExitCode != 0 && registration.ExitCode != unchecked((int)0x8009000F))
                throw new InvalidOperationException($"Windows rejected virtual passkey registration (0x{registration.ExitCode:X8}).");
        }
        catch (Exception ex)
        {
            if (packageChanged) RollBackProviderPackage(previous, rollbackPackagePath);
            if ((uint)ex.HResult == 0x800B0109 || ex.Message.Contains("0x800B0109", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Windows package deployment failed (0x800B0109): The package certificate is not trusted by Windows.\n\n" +
                    "If you are testing a development build prior to SignPath certification, please re-run Setup and select 'Register certificate into Trusted People', or import the certificate into the Trusted People store.", ex);
            }
            throw;
        }
    }

    private static ProviderPackageState? ReadInstalledProviderState()
    {
        try
        {
            var pm = new Windows.Management.Deployment.PackageManager();
            var target = System.Linq.Enumerable.FirstOrDefault(pm.FindPackagesForUser(string.Empty), p => p.Id.Name == "DarksFIDO2.Provider");
            if (target != null)
            {
                return new ProviderPackageState
                {
                    PackageFullName = target.Id.FullName,
                    Version = $"{target.Id.Version.Major}.{target.Id.Version.Minor}.{target.Id.Version.Build}.{target.Id.Version.Revision}"
                };
            }
        }
        catch { }
        return null;
    }

    private static void RollBackProviderPackage(ProviderPackageState? previous, string? rollbackPackagePath)
    {
        bool canRestorePrevious = previous is not null &&
                                  !string.IsNullOrWhiteSpace(rollbackPackagePath) &&
                                  File.Exists(rollbackPackagePath);
        if (previous is not null && !canRestorePrevious) return;
        try
        {
            var pm = new Windows.Management.Deployment.PackageManager();
            var target = System.Linq.Enumerable.FirstOrDefault(pm.FindPackagesForUser(string.Empty), p => p.Id.Name == "DarksFIDO2.Provider");
            if (target != null)
            {
                pm.RemovePackageAsync(target.Id.FullName).AsTask().GetAwaiter().GetResult();
            }
            if (canRestorePrevious)
            {
                pm.AddPackageAsync(new Uri(rollbackPackagePath!), null, Windows.Management.Deployment.DeploymentOptions.ForceApplicationShutdown).AsTask().GetAwaiter().GetResult();
                string alias = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "darksfido2-provider.exe");
                if (File.Exists(alias))
                {
                    using System.Diagnostics.Process? registration = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(alias, "--register") { UseShellExecute = false, CreateNoWindow = true });
                    registration?.WaitForExit(30_000);
                }
            }
        }
        catch
        {
            // Preserve the installation error. The application-file transaction still
            // restores the previous desktop installation.
        }
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
        bool rollbackRoot = string.Equals(Path.GetDirectoryName(fullRoot), Path.GetDirectoryName(expectedRoot), StringComparison.OrdinalIgnoreCase) &&
                            Path.GetFileName(fullRoot).StartsWith(Path.GetFileName(expectedRoot) + ".rollback-", StringComparison.OrdinalIgnoreCase);
        if ((!fullRoot.Equals(expectedRoot, StringComparison.OrdinalIgnoreCase) &&
             !fullRoot.Equals(legacyRoot, StringComparison.OrdinalIgnoreCase) &&
             !rollbackRoot) || !Directory.Exists(fullRoot)) return;
        if ((File.GetAttributes(fullRoot) & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(fullRoot, recursive: false);
            return;
        }
        DeleteContents(fullRoot, preserveFile is null ? null : Path.GetFullPath(preserveFile));
        if (preserveFile is null) Directory.Delete(fullRoot, recursive: false);
    }

    private sealed class ProviderPackageState
    {
        public string PackageFullName { get; set; } = "";
        public string Version { get; set; } = "";
        [System.Text.Json.Serialization.JsonIgnore]
        public Version ParsedVersion => System.Version.Parse(Version);
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

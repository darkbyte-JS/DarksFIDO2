namespace DarksFIDO2.Core;

public sealed class AppPaths
{
    public AppPaths(string? baseDirectory = null)
    {
        BaseDirectory = Path.GetFullPath(baseDirectory ?? ResolveDefaultBaseDirectory());
        ProfilesDirectory = Path.Combine(BaseDirectory, "profiles");
        Directory.CreateDirectory(ProfilesDirectory);
    }

    public string BaseDirectory { get; }
    public string ProfilesDirectory { get; }
    public string IndexPath => Path.Combine(BaseDirectory, "profiles.index");
    public string ProfileDirectory(Guid id) => Path.Combine(ProfilesDirectory, id.ToString("N"));
    public string MetadataPath(Guid id) => Path.Combine(ProfileDirectory(id), "profile.meta");
    public string VaultPath(Guid id) => Path.Combine(ProfileDirectory(id), "vault.dfv");

    public static bool IsPortableMode()
    {
        string exeDir = AppContext.BaseDirectory;
        return File.Exists(Path.Combine(exeDir, "portable.mode")) ||
               Environment.GetEnvironmentVariable("DARKSFIDO2_PORTABLE") == "1";
    }

    private static string ResolveDefaultBaseDirectory()
    {
        if (IsPortableMode()) return Path.Combine(AppContext.BaseDirectory, "DarksFIDO2-Data");
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DarksFIDO2");
    }
}

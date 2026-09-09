using System.Text;

namespace DarksFIDO2.Provider;

internal static class ProviderIds
{
    internal static readonly Guid ClassId = new("AA84D912-9B38-4E8F-B37E-7C95687A2D41");
    internal static readonly Guid Aaguid = new("07F654B1-1D48-45B8-AC72-4915EFA620C1");
    internal const string Name = "Darks FIDO2 virtual passkey";

    internal static byte[] AuthenticatorInfo()
    {
        const string prefix = "A50182684649444F5F325F30684649444F5F325F310350";
        const string suffix = "04A362726BF5627570F5627576F5098168696E7465726E616C0A81A263616C672664747970656A7075626C69632D6B6579";
        return Convert.FromHexString(prefix + Aaguid.ToString("N").ToUpperInvariant() + suffix);
    }

    internal static byte[] LogoSvgBase64()
    {
        const string svg = "<svg xmlns='http://www.w3.org/2000/svg' version='1.1' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='#111827'/><path d='M20 30a12 12 0 1 1 9 11.6V50h-7v-7h-5v-7h12a6 6 0 1 0-3-6z' fill='#7c3aed'/><circle cx='38' cy='26' r='3' fill='white'/></svg>";
        return Encoding.Unicode.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(svg)) + "\0");
    }
}

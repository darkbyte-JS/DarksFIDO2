using System.Globalization;
using System.Security.Cryptography;

namespace DarksFIDO2.Core;

public static class TotpService
{
    public static TotpCode GetCode(TotpEntry entry, DateTimeOffset? now = null)
    {
        if (entry is null || entry.Period is < 5 or > 300 || entry.Digits is not (6 or 8) ||
            entry.Algorithm is not ("SHA1" or "SHA256" or "SHA512"))
            throw new ArgumentException("The TOTP generator settings are invalid.", nameof(entry));
        DateTimeOffset current = now ?? DateTimeOffset.UtcNow;
        long unix = current.ToUnixTimeSeconds();
        long counter = unix / entry.Period;
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
        byte[] key = DecodeBase32(entry.SecretBase32);
        byte[] hash;
        try
        {
            hash = entry.Algorithm.ToUpperInvariant() switch
            {
                "SHA256" => HMACSHA256.HashData(key, counterBytes),
                "SHA512" => HMACSHA512.HashData(key, counterBytes),
#pragma warning disable CA5350 // HMAC-SHA1 is required for RFC 6238 interoperability; collision attacks on raw SHA-1 do not apply to this keyed, truncated OTP construction.
                "SHA1" => HMACSHA1.HashData(key, counterBytes),
#pragma warning restore CA5350
                _ => throw new ArgumentException("The TOTP algorithm is unsupported.", nameof(entry))
            };
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
        int modulus = (int)Math.Pow(10, entry.Digits);
        string code = (binary % modulus).ToString(new string('0', entry.Digits), CultureInfo.InvariantCulture);
        int remaining = entry.Period - (int)(unix % entry.Period);
        CryptographicOperations.ZeroMemory(hash);
        return new TotpCode(code, remaining, remaining / (double)entry.Period);
    }

    public static TotpEntry ParseOtpAuthUri(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 16 * 1024)
            throw new FormatException("The otpauth URI has an invalid length.");
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri? uri) ||
            !uri.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase) ||
            !uri.Host.Equals("totp", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("Expected an otpauth://totp URI.");

        string label = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        if (label.Length > 768) throw new FormatException("The TOTP account label is too long.");
        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = part.Split('=', 2);
            string key = Uri.UnescapeDataString(pair[0]);
            string item = pair.Length > 1 ? Uri.UnescapeDataString(pair[1]) : "";
            if (key.Length > 64 || item.Length > 8 * 1024 || !query.TryAdd(key, item))
                throw new FormatException("The TOTP URI contains invalid or duplicate parameters.");
        }
        if (!query.TryGetValue("secret", out string? secret) || string.IsNullOrWhiteSpace(secret))
            throw new FormatException("The URI does not contain a TOTP secret.");
        _ = DecodeBase32(secret);

        string issuerFromLabel = "";
        string account = label;
        int separator = label.IndexOf(':');
        if (separator >= 0)
        {
            issuerFromLabel = label[..separator].Trim();
            account = label[(separator + 1)..].Trim();
        }
        string issuer = query.GetValueOrDefault("issuer", issuerFromLabel).Trim();
        if (issuer.Length > 256 || account.Length is < 1 or > 512 || issuer.IndexOf('\0') >= 0 || account.IndexOf('\0') >= 0)
            throw new FormatException("The TOTP issuer or account name is invalid.");
        int digits = ParseBounded(query.GetValueOrDefault("digits"), 6, 6, 8);
        int period = ParseBounded(query.GetValueOrDefault("period"), 30, 5, 300);
        string algorithm = query.GetValueOrDefault("algorithm", "SHA1").ToUpperInvariant();
        if (algorithm is not ("SHA1" or "SHA256" or "SHA512")) throw new FormatException("Unsupported TOTP algorithm.");
        return new TotpEntry
        {
            Issuer = issuer,
            Account = account,
            SecretBase32 = NormalizeBase32(secret),
            Digits = digits,
            Period = period,
            Algorithm = algorithm
        };
    }

    public static byte[] DecodeBase32(string encoded)
    {
        if (encoded is null || encoded.Length > 8 * 1024) throw new FormatException("The Base32 secret is too long.");
        string normalized = NormalizeBase32(encoded);
        if (normalized.Length is < 8 or > 4_096) throw new FormatException("The Base32 secret has an invalid length.");
        var output = new List<byte>(normalized.Length * 5 / 8);
        int buffer = 0;
        int bitsLeft = 0;
        foreach (char c in normalized)
        {
            int value = c is >= 'A' and <= 'Z' ? c - 'A' : c is >= '2' and <= '7' ? c - '2' + 26 : -1;
            if (value < 0) throw new FormatException("The TOTP secret is not valid Base32.");
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)(buffer >> bitsLeft));
                buffer &= (1 << bitsLeft) - 1;
            }
        }
        return output.ToArray();
    }

    private static string NormalizeBase32(string value) => new(value.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '=').Select(char.ToUpperInvariant).ToArray());
    private static int ParseBounded(string? value, int fallback, int min, int max) => int.TryParse(value, out int parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

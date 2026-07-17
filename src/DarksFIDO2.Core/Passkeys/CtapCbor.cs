using System.Buffers.Binary;
using System.Text;

namespace DarksFIDO2.Core.Passkeys;

public static class CtapCbor
{
    public const int MaximumDocumentBytes = 1024 * 1024;
    public const int MaximumCollectionItems = 1024;
    public const int MaximumNestingDepth = 24;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static object? Decode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > MaximumDocumentBytes)
            throw new FormatException("The CTAP CBOR payload has an invalid size.");
        var reader = new Reader(data.ToArray());
        object? value;
        try { value = reader.Read(0); }
        catch (OverflowException ex) { throw new FormatException("A CTAP CBOR length or integer is outside the supported range.", ex); }
        if (!reader.AtEnd) throw new FormatException("Trailing data in CTAP CBOR payload.");
        return value;
    }

    public static byte[] Encode(object? value)
    {
        using var output = new MemoryStream();
        Write(output, value);
        return output.ToArray();
    }

    public static Dictionary<object, object?> Map(object? value) =>
        value as Dictionary<object, object?> ?? throw new FormatException("Expected a CBOR map.");

    public static List<object?> Array(object? value) =>
        value as List<object?> ?? throw new FormatException("Expected a CBOR array.");

    public static byte[] Bytes(object? value) =>
        value as byte[] ?? throw new FormatException("Expected a CBOR byte string.");

    public static string Text(object? value) =>
        value as string ?? throw new FormatException("Expected a CBOR text string.");

    public static long Integer(object? value) =>
        value is long number ? number : throw new FormatException("Expected a CBOR integer.");

    private static void Write(Stream output, object? value)
    {
        switch (value)
        {
            case null: output.WriteByte(0xF6); break;
            case bool boolean: output.WriteByte(boolean ? (byte)0xF5 : (byte)0xF4); break;
            case byte unsigned: WriteInteger(output, unsigned); break;
            case int integer: WriteInteger(output, integer); break;
            case long integer: WriteInteger(output, integer); break;
            case uint unsigned: WriteUnsigned(output, 0, unsigned); break;
            case byte[] bytes:
                WriteUnsigned(output, 2, (ulong)bytes.Length); output.Write(bytes); break;
            case string text:
                byte[] utf8 = Encoding.UTF8.GetBytes(text);
                WriteUnsigned(output, 3, (ulong)utf8.Length); output.Write(utf8); break;
            case IReadOnlyList<object?> array:
                WriteUnsigned(output, 4, (ulong)array.Count);
                foreach (object? item in array) Write(output, item);
                break;
            case IDictionary<object, object?> map:
                WriteUnsigned(output, 5, (ulong)map.Count);
                foreach ((object key, object? item) in map) { Write(output, key); Write(output, item); }
                break;
            default: throw new ArgumentException($"Unsupported CBOR value type {value.GetType().Name}.");
        }
    }

    private static void WriteInteger(Stream output, long value)
    {
        if (value >= 0) WriteUnsigned(output, 0, (ulong)value);
        else WriteUnsigned(output, 1, (ulong)(-1 - value));
    }

    private static void WriteUnsigned(Stream output, byte major, ulong value)
    {
        if (value < 24) { output.WriteByte((byte)((major << 5) | (byte)value)); return; }
        Span<byte> buffer = stackalloc byte[9];
        if (value <= byte.MaxValue) { output.WriteByte((byte)((major << 5) | 24)); output.WriteByte((byte)value); }
        else if (value <= ushort.MaxValue) { output.WriteByte((byte)((major << 5) | 25)); BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value); output.Write(buffer[..2]); }
        else if (value <= uint.MaxValue) { output.WriteByte((byte)((major << 5) | 26)); BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)value); output.Write(buffer[..4]); }
        else { output.WriteByte((byte)((major << 5) | 27)); BinaryPrimitives.WriteUInt64BigEndian(buffer, value); output.Write(buffer[..8]); }
    }

    private sealed class Reader(byte[] data)
    {
        private int _offset;
        public bool AtEnd => _offset == data.Length;

        public object? Read(int depth)
        {
            if (depth > MaximumNestingDepth) throw new FormatException("The CTAP CBOR payload is nested too deeply.");
            byte initial = Next();
            int major = initial >> 5;
            int additional = initial & 31;
            if (major == 7)
                return additional switch { 20 => false, 21 => true, 22 => null, _ => throw new FormatException("Unsupported CBOR simple value.") };
            ulong length = ReadLength(additional);
            return major switch
            {
                0 => checked((long)length),
                1 => checked(-1L - (long)length),
                2 => Take(checked((int)length)),
                3 => DecodeText(checked((int)length)),
                4 => ReadArray(checked((int)length), depth),
                5 => ReadMap(checked((int)length), depth),
                _ => throw new FormatException("Unsupported CTAP CBOR type.")
            };
        }

        private List<object?> ReadArray(int count, int depth)
        {
            ValidateCollectionCount(count, minimumBytesPerItem: 1);
            var result = new List<object?>(count);
            for (int i = 0; i < count; i++) result.Add(Read(depth + 1));
            return result;
        }

        private Dictionary<object, object?> ReadMap(int count, int depth)
        {
            ValidateCollectionCount(count, minimumBytesPerItem: 2);
            var result = new Dictionary<object, object?>(count);
            for (int i = 0; i < count; i++)
            {
                object key = Read(depth + 1) ?? throw new FormatException("Null CBOR map key.");
                if (!result.TryAdd(key, Read(depth + 1))) throw new FormatException("Duplicate CBOR map key.");
            }
            return result;
        }

        private string DecodeText(int count)
        {
            try { return StrictUtf8.GetString(Take(count)); }
            catch (DecoderFallbackException ex) { throw new FormatException("Invalid UTF-8 in CTAP CBOR text.", ex); }
        }

        private void ValidateCollectionCount(int count, int minimumBytesPerItem)
        {
            if (count < 0 || count > MaximumCollectionItems || count > (data.Length - _offset) / minimumBytesPerItem)
                throw new FormatException("The CTAP CBOR collection is too large or truncated.");
        }

        private ulong ReadLength(int additional) => additional switch
        {
            < 24 => (ulong)additional,
            24 => Next(),
            25 => BinaryPrimitives.ReadUInt16BigEndian(Take(2)),
            26 => BinaryPrimitives.ReadUInt32BigEndian(Take(4)),
            27 => BinaryPrimitives.ReadUInt64BigEndian(Take(8)),
            _ => throw new FormatException("Indefinite-length CBOR is not accepted for CTAP messages.")
        };

        private byte Next()
        {
            if (_offset >= data.Length) throw new FormatException("Truncated CTAP CBOR payload.");
            return data[_offset++];
        }

        private byte[] Take(int count)
        {
            if (count < 0 || count > data.Length - _offset) throw new FormatException("Truncated CTAP CBOR payload.");
            byte[] output = data.AsSpan(_offset, count).ToArray();
            _offset += count;
            return output;
        }
    }
}

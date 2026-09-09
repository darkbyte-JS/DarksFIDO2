using System.Buffers.Binary;
using System.Text;

namespace DarksFIDO2.Core.Passkeys;

public static class CtapCbor
{
    public const int MaximumDocumentBytes = 1024 * 1024;
    public const int MaximumCollectionItems = 1024;
    public const int MaximumDecodedItems = 4096;
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

    public static object? DecodeFirst(ReadOnlySpan<byte> data, out int bytesConsumed)
    {
        if (data.IsEmpty || data.Length > MaximumDocumentBytes)
            throw new FormatException("The CTAP CBOR payload has an invalid size.");
        var reader = new Reader(data.ToArray());
        object? value;
        try { value = reader.Read(0); }
        catch (OverflowException ex) { throw new FormatException("A CTAP CBOR length or integer is outside the supported range.", ex); }
        bytesConsumed = reader.Offset;
        return value;
    }

    public static byte[] Encode(object? value)
    {
        using var output = new MemoryStream();
        int itemCount = 0;
        Write(output, value, 0, ref itemCount);
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

    private static void Write(MemoryStream output, object? value, int depth, ref int itemCount)
    {
        if (depth > MaximumNestingDepth)
            throw new ArgumentException("The CTAP CBOR value is nested too deeply.", nameof(value));
        if (++itemCount > MaximumDecodedItems)
            throw new ArgumentException("The CTAP CBOR value contains too many items.", nameof(value));

        switch (value)
        {
            case null: WriteByte(output, 0xF6); break;
            case bool boolean: WriteByte(output, boolean ? (byte)0xF5 : (byte)0xF4); break;
            case byte unsigned: WriteInteger(output, unsigned); break;
            case int integer: WriteInteger(output, integer); break;
            case long integer: WriteInteger(output, integer); break;
            case uint unsigned: WriteUnsigned(output, 0, unsigned); break;
            case byte[] bytes:
                if (bytes.Length > MaximumDocumentBytes) throw new ArgumentException("The CTAP CBOR byte string is too large.", nameof(value));
                WriteUnsigned(output, 2, (ulong)bytes.Length); WriteBytes(output, bytes); break;
            case string text:
                byte[] utf8;
                try
                {
                    int byteCount = StrictUtf8.GetByteCount(text);
                    if (byteCount > MaximumDocumentBytes) throw new ArgumentException("The CTAP CBOR text string is too large.", nameof(value));
                    utf8 = StrictUtf8.GetBytes(text);
                }
                catch (EncoderFallbackException ex)
                {
                    throw new ArgumentException("The CTAP CBOR text contains invalid Unicode.", nameof(value), ex);
                }
                WriteUnsigned(output, 3, (ulong)utf8.Length); WriteBytes(output, utf8); break;
            case IReadOnlyList<object?> array:
                if (array.Count > MaximumCollectionItems) throw new ArgumentException("The CTAP CBOR array is too large.", nameof(value));
                WriteUnsigned(output, 4, (ulong)array.Count);
                foreach (object? item in array) Write(output, item, depth + 1, ref itemCount);
                break;
            case IDictionary<object, object?> map:
                WriteMap(output, map, depth, ref itemCount);
                break;
            default: throw new ArgumentException($"Unsupported CBOR value type {value.GetType().Name}.");
        }
    }

    private static void WriteMap(MemoryStream output, IDictionary<object, object?> map, int depth, ref int itemCount)
    {
        if (map.Count > MaximumCollectionItems) throw new ArgumentException("The CTAP CBOR map is too large.", nameof(map));
        var entries = new List<EncodedMapEntry>(map.Count);
        int totalKeyBytes = 0;
        foreach ((object? key, object? item) in map)
        {
            if (key is null || !IsSupportedMapKey(key))
                throw new ArgumentException("CTAP CBOR map keys must be integers, byte strings, text strings, or booleans.", nameof(map));
            using var keyOutput = new MemoryStream();
            Write(keyOutput, key, depth + 1, ref itemCount);
            byte[] encodedKey = keyOutput.ToArray();
            totalKeyBytes = checked(totalKeyBytes + encodedKey.Length);
            if (totalKeyBytes > MaximumDocumentBytes) throw new ArgumentException("The CTAP CBOR map keys are too large.", nameof(map));
            entries.Add(new EncodedMapEntry(encodedKey, item));
        }

        entries.Sort(static (left, right) => CompareEncodedKeys(left.Key, right.Key));
        for (int i = 1; i < entries.Count; i++)
            if (CompareEncodedKeys(entries[i - 1].Key, entries[i].Key) == 0)
                throw new ArgumentException("The CTAP CBOR map contains duplicate keys.", nameof(map));

        WriteUnsigned(output, 5, (ulong)entries.Count);
        foreach (EncodedMapEntry entry in entries)
        {
            WriteBytes(output, entry.Key);
            Write(output, entry.Value, depth + 1, ref itemCount);
        }
    }

    private static void WriteInteger(MemoryStream output, long value)
    {
        if (value >= 0) WriteUnsigned(output, 0, (ulong)value);
        else WriteUnsigned(output, 1, (ulong)(-1 - value));
    }

    private static void WriteUnsigned(MemoryStream output, byte major, ulong value)
    {
        if (value < 24) { WriteByte(output, (byte)((major << 5) | (byte)value)); return; }
        Span<byte> buffer = stackalloc byte[9];
        if (value <= byte.MaxValue) { WriteByte(output, (byte)((major << 5) | 24)); WriteByte(output, (byte)value); }
        else if (value <= ushort.MaxValue) { WriteByte(output, (byte)((major << 5) | 25)); BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value); WriteBytes(output, buffer[..2]); }
        else if (value <= uint.MaxValue) { WriteByte(output, (byte)((major << 5) | 26)); BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)value); WriteBytes(output, buffer[..4]); }
        else { WriteByte(output, (byte)((major << 5) | 27)); BinaryPrimitives.WriteUInt64BigEndian(buffer, value); WriteBytes(output, buffer[..8]); }
    }

    private static void WriteByte(MemoryStream output, byte value)
    {
        EnsureOutputCapacity(output, 1);
        output.WriteByte(value);
    }

    private static void WriteBytes(MemoryStream output, ReadOnlySpan<byte> value)
    {
        EnsureOutputCapacity(output, value.Length);
        output.Write(value);
    }

    private static void EnsureOutputCapacity(MemoryStream output, int additionalBytes)
    {
        if (additionalBytes < 0 || output.Length > MaximumDocumentBytes - (long)additionalBytes)
            throw new ArgumentException("The encoded CTAP CBOR document is too large.");
    }

    private static bool IsSupportedMapKey(object value) => value is long or int or uint or byte or string or byte[] or bool;

    private static int CompareEncodedKeys(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        int majorComparison = (left[0] >> 5).CompareTo(right[0] >> 5);
        if (majorComparison != 0) return majorComparison;
        int lengthComparison = left.Length.CompareTo(right.Length);
        if (lengthComparison != 0) return lengthComparison;
        return left.SequenceCompareTo(right);
    }

    private readonly record struct EncodedMapEntry(byte[] Key, object? Value);

    private sealed class Reader(byte[] data)
    {
        private int _offset;
        private int _itemCount;
        public bool AtEnd => _offset == data.Length;
        public int Offset => _offset;

        public object? Read(int depth)
        {
            if (depth > MaximumNestingDepth) throw new FormatException("The CTAP CBOR payload is nested too deeply.");
            if (++_itemCount > MaximumDecodedItems) throw new FormatException("The CTAP CBOR payload contains too many values.");
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
            var result = new Dictionary<object, object?>(count, CborKeyComparer.Instance);
            byte[]? previousKey = null;
            for (int i = 0; i < count; i++)
            {
                int keyOffset = _offset;
                object key = Read(depth + 1) ?? throw new FormatException("Null CBOR map key.");
                if (!IsSupportedMapKey(key)) throw new FormatException("Unsupported CTAP CBOR map key type.");
                byte[] encodedKey = data.AsSpan(keyOffset, _offset - keyOffset).ToArray();
                if (previousKey is not null && CompareEncodedKeys(previousKey, encodedKey) >= 0)
                    throw new FormatException("CTAP CBOR map keys are not canonical or contain a duplicate.");
                previousKey = encodedKey;
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

        private ulong ReadLength(int additional)
        {
            ulong value = additional switch
            {
                < 24 => (ulong)additional,
                24 => Next(),
                25 => BinaryPrimitives.ReadUInt16BigEndian(Take(2)),
                26 => BinaryPrimitives.ReadUInt32BigEndian(Take(4)),
                27 => BinaryPrimitives.ReadUInt64BigEndian(Take(8)),
                _ => throw new FormatException("Indefinite-length CBOR is not accepted for CTAP messages.")
            };
            if (additional == 24 && value < 24 ||
                additional == 25 && value <= byte.MaxValue ||
                additional == 26 && value <= ushort.MaxValue ||
                additional == 27 && value <= uint.MaxValue)
                throw new FormatException("CTAP CBOR integers and lengths must use their shortest encoding.");
            return value;
        }

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

    private sealed class CborKeyComparer : IEqualityComparer<object>
    {
        public static readonly CborKeyComparer Instance = new();

        public new bool Equals(object? left, object? right)
        {
            if (ReferenceEquals(left, right)) return true;
            if (left is byte[] leftBytes && right is byte[] rightBytes) return leftBytes.AsSpan().SequenceEqual(rightBytes);
            return left?.Equals(right) == true;
        }

        public int GetHashCode(object value)
        {
            if (value is not byte[] bytes) return value.GetHashCode();
            var hash = new HashCode();
            hash.AddBytes(bytes);
            return hash.ToHashCode();
        }
    }
}

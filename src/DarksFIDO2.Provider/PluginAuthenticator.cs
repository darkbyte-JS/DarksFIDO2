using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using DarksFIDO2.Core.Passkeys;

namespace DarksFIDO2.Provider;

[ComVisible(true)]
[Guid("D26BCF6F-B54C-43FF-9F06-D5BF148625F7")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IPluginAuthenticator
{
    [PreserveSig] int MakeCredential(IntPtr request, IntPtr response);
    [PreserveSig] int GetAssertion(IntPtr request, IntPtr response);
    [PreserveSig] int CancelOperation(IntPtr request);
    [PreserveSig] int GetLockStatus(IntPtr status);
}

[ComVisible(true)]
[Guid("00000001-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IClassFactory
{
    [PreserveSig] int CreateInstance(IntPtr outer, ref Guid interfaceId, out IntPtr instance);
    [PreserveSig] int LockServer([MarshalAs(UnmanagedType.Bool)] bool value);
}

[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class PluginClassFactory : IClassFactory
{
    public int CreateInstance(IntPtr outer, ref Guid interfaceId, out IntPtr instance)
    {
        instance = IntPtr.Zero;
        if (outer != IntPtr.Zero) return unchecked((int)0x80040110);
        var authenticator = new PluginAuthenticator();
        IntPtr unknown = Marshal.GetIUnknownForObject(authenticator);
        try { return Marshal.QueryInterface(unknown, in interfaceId, out instance); }
        finally { Marshal.Release(unknown); }
    }

    public int LockServer(bool value) => 0;
}

[ComVisible(true)]
[Guid("AA84D912-9B38-4E8F-B37E-7C95687A2D41")]
[ClassInterface(ClassInterfaceType.None)]
[ComDefaultInterface(typeof(IPluginAuthenticator))]
public sealed class PluginAuthenticator : IPluginAuthenticator
{
    private static readonly Guid Aaguid = ProviderIds.Aaguid;
    private static readonly SemaphoreSlim OperationGate = new(1, 1);
    private static readonly ConcurrentDictionary<Guid, CancellationTokenSource> Operations = new();
    private readonly SoftwarePasskeyStore _store = new();
    private readonly PasskeyProviderContext _profileContext = new();

    public int MakeCredential(IntPtr requestPointer, IntPtr responsePointer) =>
        Run(requestPointer, responsePointer, makeCredential: true);

    public int GetAssertion(IntPtr requestPointer, IntPtr responsePointer) =>
        Run(requestPointer, responsePointer, makeCredential: false);

    public int CancelOperation(IntPtr requestPointer)
    {
        if (requestPointer == IntPtr.Zero) return NativeMethods.EInvalidArg;
        NativeMethods.PluginCancelRequest request = Marshal.PtrToStructure<NativeMethods.PluginCancelRequest>(requestPointer);
        if (Operations.TryGetValue(request.TransactionId, out CancellationTokenSource? cancellation)) cancellation.Cancel();
        return 0;
    }

    public int GetLockStatus(IntPtr status)
    {
        if (status == IntPtr.Zero) return NativeMethods.EInvalidArg;
        Marshal.WriteInt32(status, _profileContext.GetActiveProfileId() is null ? 0 : 1);
        return 0;
    }

    private int Run(IntPtr requestPointer, IntPtr responsePointer, bool makeCredential)
    {
        if (requestPointer == IntPtr.Zero || responsePointer == IntPtr.Zero) return NativeMethods.EInvalidArg;
        Marshal.StructureToPtr(new NativeMethods.PluginOperationResponse(), responsePointer, false);
        string operationName = makeCredential ? "MakeCredential" : "GetAssertion";
        Guid transactionId = Guid.Empty;
        if (!OperationGate.Wait(TimeSpan.FromSeconds(5)))
        {
            ProviderLog.Write(transactionId, operationName, "Rejected because another provider request remained busy for five seconds.");
            return unchecked((int)0x800700AA);
        }
        byte[] encoded = [];
        byte[] requestSignature = [];
        try
        {
            NativeMethods.PluginOperationRequest request = Marshal.PtrToStructure<NativeMethods.PluginOperationRequest>(requestPointer);
            transactionId = request.TransactionId;
            ProviderLog.Write(transactionId, operationName, "Request received.");
            if (request.TransactionId == Guid.Empty || request.RequestType != 1 || request.EncodedRequestLength == 0 ||
                request.EncodedRequest == IntPtr.Zero || request.RequestSignatureLength == 0 || request.RequestSignature == IntPtr.Zero)
                return NativeMethods.EInvalidArg;
            encoded = Copy(request.EncodedRequest, request.EncodedRequestLength, CtapCbor.MaximumDocumentBytes);
            requestSignature = Copy(request.RequestSignature, request.RequestSignatureLength, 16 * 1024);
            if (!NativeMethods.VerifyPlatformOperation(encoded, requestSignature))
            {
                ProviderLog.Write(transactionId, operationName, "Windows operation signature verification failed.");
                return unchecked((int)0x80096010);
            }

            using var cancellation = new CancellationTokenSource();
            if (!Operations.TryAdd(request.TransactionId, cancellation)) return unchecked((int)0x800700AA);
            try
            {
                byte[] response = [];
                try
                {
                    response = makeCredential
                        ? MakeCredentialCore(request, encoded, cancellation.Token)
                        : GetAssertionCore(request, encoded, cancellation.Token);
                    if (response.Length is < 1 or > CtapCbor.MaximumDocumentBytes) throw new FormatException("Invalid CTAP response size.");
                    IntPtr buffer = Marshal.AllocCoTaskMem(response.Length);
                    try
                    {
                        Marshal.Copy(response, 0, buffer, response.Length);
                        Marshal.StructureToPtr(new NativeMethods.PluginOperationResponse
                        {
                            EncodedResponseLength = (uint)response.Length,
                            EncodedResponse = buffer
                        }, responsePointer, false);
                    }
                    catch { Marshal.FreeCoTaskMem(buffer); throw; }
                    ProviderLog.Write(transactionId, operationName, $"Completed successfully ({response.Length} response bytes).");
                    return 0;
                }
                finally { if (response.Length > 0) CryptographicOperations.ZeroMemory(response); }
            }
            finally { Operations.TryRemove(request.TransactionId, out _); }
        }
        catch (OperationCanceledException) { ProviderLog.Write(transactionId, operationName, "Cancelled during user verification."); return NativeMethods.NteUserCancelled; }
        catch (KeyNotFoundException ex) { ProviderLog.Write(transactionId, operationName, ex.Message); return NativeMethods.NteNotFound; }
        catch (FormatException ex) { ProviderLog.Write(transactionId, operationName, "Invalid request: " + ex.Message); return NativeMethods.EInvalidArg; }
        catch (CryptographicException ex) { ProviderLog.Write(transactionId, operationName, "Cryptographic failure: " + ex.Message); return NativeMethods.EFail; }
        catch (Exception ex) { ProviderLog.Write(transactionId, operationName, "Unexpected failure: " + ex.GetType().Name); return NativeMethods.EFail; }
        finally
        {
            if (encoded.Length > 0) CryptographicOperations.ZeroMemory(encoded);
            if (requestSignature.Length > 0) CryptographicOperations.ZeroMemory(requestSignature);
            OperationGate.Release();
        }
    }

    private byte[] MakeCredentialCore(NativeMethods.PluginOperationRequest operation, byte[] encoded, CancellationToken cancellation)
    {
        Dictionary<object, object?> request = CtapCbor.Map(CtapCbor.Decode(encoded));
        byte[] clientDataHash = CtapCbor.Bytes(Get(request, 1));
        Dictionary<object, object?> rp = CtapCbor.Map(Get(request, 2));
        Dictionary<object, object?> user = CtapCbor.Map(Get(request, 3));
        string rpId = CtapCbor.Text(Get(rp, "id"));
        string rpName = TryText(rp, "name") ?? rpId;
        byte[] userId = CtapCbor.Bytes(Get(user, "id"));
        string userName = CtapCbor.Text(Get(user, "name"));
        string displayName = TryText(user, "displayName") ?? userName;
        ValidateIdentity(rpId, rpName, userId, userName, displayName);
        ProviderLog.Write(operation.TransactionId, "MakeCredential", $"Validated request for RP {rpId}.");
        if (clientDataHash.Length != 32 || !SupportsEs256(Get(request, 4))) throw new FormatException("Unsupported passkey request.");

        Guid profileId = _profileContext.GetActiveProfileId()
            ?? throw new KeyNotFoundException("No Darks FIDO2 profile is currently unlocked. Unlock the intended profile before creating a passkey.");

        foreach (byte[] excluded in ReadCredentialList(request, 5))
            if (_store.Find(profileId, rpId, [excluded]) is not null) throw new CryptographicException("Credential excluded by the relying party.");

        cancellation.ThrowIfCancellationRequested();
        if (!NativeMethods.VerifyUser(operation.Window, operation.TransactionId, userName, encoded)) throw new OperationCanceledException();
        cancellation.ThrowIfCancellationRequested();

        SoftwarePasskeyCredential credential = _store.Create(rpId, rpName, userId, userName, displayName, profileId);
        int metadataHr = NativeMethods.AddCredentialMetadata(credential);
        if (metadataHr < 0)
        {
            _store.Remove(profileId, credential.CredentialId);
            ProviderLog.Write(operation.TransactionId, "MakeCredential", $"Windows rejected credential metadata with HRESULT 0x{metadataHr:X8}; rolled back the key.");
            Marshal.ThrowExceptionForHR(metadataHr);
        }
        ProviderLog.Write(operation.TransactionId, "MakeCredential", $"Created {credential.RpId} credential {Convert.ToHexString(credential.CredentialId)[..12]} (profile {profileId:D}, {(credential.HardwareBacked ? "TPM" : "software KSP")}).");

        byte[] cose = _store.PublicCoseKey(credential);
        byte[] authenticatorData = BuildRegistrationAuthenticatorData(rpId, credential.CredentialId, cose);
        return CtapCbor.Encode(new Dictionary<object, object?>
        {
            [1L] = "none",
            [2L] = authenticatorData,
            [3L] = new Dictionary<object, object?>()
        });
    }

    private byte[] GetAssertionCore(NativeMethods.PluginOperationRequest operation, byte[] encoded, CancellationToken cancellation)
    {
        Dictionary<object, object?> request = CtapCbor.Map(CtapCbor.Decode(encoded));
        string rpId = CtapCbor.Text(Get(request, 1));
        byte[] clientDataHash = CtapCbor.Bytes(Get(request, 2));
        ValidateRpId(rpId);
        if (clientDataHash.Length != 32) throw new FormatException("Invalid client data hash.");
        Guid profileId = _profileContext.GetActiveProfileId()
            ?? throw new KeyNotFoundException("No Darks FIDO2 profile is currently unlocked. Unlock the profile that owns this passkey.");
        SoftwarePasskeyCredential credential = _store.Find(profileId, rpId, ReadCredentialList(request, 3))
            ?? throw new KeyNotFoundException($"No {rpId} passkey belongs to the currently unlocked Darks FIDO2 profile.");
        ProviderLog.Write(operation.TransactionId, "GetAssertion", $"Matched {credential.RpId} credential {Convert.ToHexString(credential.CredentialId)[..12]}.");

        cancellation.ThrowIfCancellationRequested();
        if (!NativeMethods.VerifyUser(operation.Window, operation.TransactionId, credential.UserName, encoded)) throw new OperationCanceledException();
        cancellation.ThrowIfCancellationRequested();

        uint counter = _store.IncrementCounter(credential);
        byte[] authenticatorData = BuildAssertionAuthenticatorData(rpId, counter);
        byte[] signed = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signed, 0); clientDataHash.CopyTo(signed, authenticatorData.Length);
        byte[] signature = _store.Sign(credential, signed);
        CryptographicOperations.ZeroMemory(signed);

        return CtapCbor.Encode(new Dictionary<object, object?>
        {
            [1L] = new Dictionary<object, object?> { ["id"] = credential.CredentialId, ["type"] = "public-key" },
            [2L] = authenticatorData,
            [3L] = signature,
            [4L] = new Dictionary<object, object?> { ["id"] = credential.UserId, ["name"] = credential.UserName, ["displayName"] = credential.UserDisplayName },
            [5L] = 1L
        });
    }

    private static byte[] BuildRegistrationAuthenticatorData(string rpId, byte[] credentialId, byte[] cose)
    {
        byte[] output = new byte[32 + 1 + 4 + 16 + 2 + credentialId.Length + cose.Length];
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(output, 0);
        output[32] = 0x45; // user present, user verified, attested credential data
        Convert.FromHexString(Aaguid.ToString("N")).CopyTo(output, 37);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(53, 2), checked((ushort)credentialId.Length));
        credentialId.CopyTo(output, 55);
        cose.CopyTo(output, 55 + credentialId.Length);
        return output;
    }

    private static byte[] BuildAssertionAuthenticatorData(string rpId, uint counter)
    {
        byte[] output = new byte[37];
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(output, 0);
        output[32] = 0x05; // user present and user verified
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(33, 4), counter);
        return output;
    }

    private static object? Get(Dictionary<object, object?> map, object key) =>
        map.TryGetValue(key is int i ? (long)i : key, out object? value) ? value : throw new FormatException($"Missing CTAP field {key}.");

    private static string? TryText(Dictionary<object, object?> map, string key) =>
        map.TryGetValue(key, out object? value) && value is string text ? text : null;

    private static bool SupportsEs256(object? value) =>
        CtapCbor.Array(value).Any(item => CtapCbor.Map(item).TryGetValue("alg", out object? alg) && alg is long number && number == -7);

    private static IReadOnlyList<byte[]> ReadCredentialList(Dictionary<object, object?> request, int key)
    {
        if (!request.TryGetValue((long)key, out object? value)) return [];
        List<object?> entries = CtapCbor.Array(value);
        if (entries.Count > 128) throw new FormatException("The credential descriptor list is too large.");
        var result = new List<byte[]>(entries.Count);
        foreach (object? entry in entries)
        {
            Dictionary<object, object?> descriptor = CtapCbor.Map(entry);
            if (descriptor.TryGetValue("type", out object? type) && (!string.Equals(type as string, "public-key", StringComparison.Ordinal)))
                throw new FormatException("Unsupported credential descriptor type.");
            byte[] bytes = CtapCbor.Bytes(Get(descriptor, "id"));
            if (bytes.Length is < 1 or > 1_024) throw new FormatException("Invalid credential identifier length.");
            result.Add(bytes);
        }
        return result;
    }

    private static byte[] Copy(IntPtr pointer, uint length, int maximumLength)
    {
        if (length == 0) return [];
        if (pointer == IntPtr.Zero || length > maximumLength) throw new FormatException("Invalid native buffer.");
        byte[] bytes = new byte[length]; Marshal.Copy(pointer, bytes, 0, bytes.Length); return bytes;
    }

    private static void ValidateIdentity(string rpId, string rpName, byte[] userId, string userName, string displayName)
    {
        ValidateRpId(rpId);
        if (userId.Length is < 1 or > 64 || !ValidText(rpName, 0, 256) || !ValidText(userName, 1, 256) || !ValidText(displayName, 0, 256))
            throw new FormatException("Invalid passkey identity fields.");
    }

    private static void ValidateRpId(string rpId)
    {
        if (!ValidText(rpId, 1, 253) || rpId.Contains("://", StringComparison.Ordinal) || rpId.Contains('/') || rpId.Any(char.IsWhiteSpace))
            throw new FormatException("Invalid relying-party identifier.");
    }

    private static bool ValidText(string? value, int minimum, int maximum) =>
        value is not null && value.Length >= minimum && value.Length <= maximum && value.IndexOf('\0') < 0;
}

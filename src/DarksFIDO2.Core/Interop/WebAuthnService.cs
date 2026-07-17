using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using DarksFIDO2.Core.Passkeys;

namespace DarksFIDO2.Core.Interop;

public sealed class WebAuthnService
{
    private const string RpId = "darksfido2.local";
    private const string PublicKeyType = "public-key";
    private const int MaximumCredentialIdBytes = 1023;
    private const int MaximumSignatureBytes = 1024;
    private const byte UserPresentFlag = 0x01;
    private const byte UserVerifiedFlag = 0x04;
    private const byte BackupEligibleFlag = 0x08;
    private const byte BackupStateFlag = 0x10;
    private const byte AttestedCredentialDataFlag = 0x40;
    private const byte ExtensionDataFlag = 0x80;
    private static readonly byte[] ExpectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));

    public uint ApiVersion => WebAuthNGetApiVersionNumber();

    public bool IsPlatformAuthenticatorAvailable()
    {
        try
        {
            int hr = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool available);
            return hr >= 0 && available;
        }
        catch { return false; }
    }

    public IReadOnlyList<AuthenticatorInfo> EnumerateAuthenticators()
    {
        if (ApiVersion < 9) return [];
        IntPtr listPointer = IntPtr.Zero;
        try
        {
            int hr = WebAuthNGetAuthenticatorList(IntPtr.Zero, out listPointer);
            Check(hr, "enumerate authenticators");
            if (listPointer == IntPtr.Zero) throw new CryptographicException("Windows returned an empty authenticator-list pointer.");
            AuthenticatorDetailsList list = Marshal.PtrToStructure<AuthenticatorDetailsList>(listPointer);
            if (list.cAuthenticatorDetails > 1_024 || list.cAuthenticatorDetails > 0 && list.ppAuthenticatorDetails == IntPtr.Zero)
                throw new CryptographicException("Windows returned an invalid authenticator list.");
            var output = new List<AuthenticatorInfo>((int)list.cAuthenticatorDetails);
            for (int i = 0; i < list.cAuthenticatorDetails; i++)
            {
                IntPtr itemPointer = Marshal.ReadIntPtr(list.ppAuthenticatorDetails, i * IntPtr.Size);
                if (itemPointer == IntPtr.Zero) throw new CryptographicException("Windows returned an empty authenticator-details pointer.");
                AuthenticatorDetails item = Marshal.PtrToStructure<AuthenticatorDetails>(itemPointer);
                if (item.cbAuthenticatorId is < 0 or > 4_096 || item.cbAuthenticatorId > 0 && item.pbAuthenticatorId == IntPtr.Zero)
                    throw new CryptographicException("Windows returned an invalid authenticator identifier.");
                byte[] id = new byte[item.cbAuthenticatorId];
                if (id.Length > 0) Marshal.Copy(item.pbAuthenticatorId, id, 0, id.Length);
                string name = Marshal.PtrToStringUni(item.pwszAuthenticatorName) ?? "Authenticator";
                if (name.Length > 512) throw new CryptographicException("Windows returned an invalid authenticator name.");
                output.Add(new AuthenticatorInfo
                {
                    Id = Convert.ToBase64String(id),
                    Name = name,
                    IsLocked = item.bLocked,
                    Kind = name.Contains("Hello", StringComparison.OrdinalIgnoreCase) ? "Platform" : "External / plugin"
                });
            }
            return output;
        }
        catch (EntryPointNotFoundException) { return []; }
        finally
        {
            if (listPointer != IntPtr.Zero) WebAuthNFreeAuthenticatorList(listPointer);
        }
    }

    public FidoKeyRecord RegisterCredential(IntPtr ownerWindow, Guid profileId, string displayName, bool usePlatformAuthenticator = false)
    {
        if (profileId == Guid.Empty || string.IsNullOrWhiteSpace(displayName) || displayName.Length > 256 || displayName.IndexOf('\0') >= 0)
            throw new ArgumentException("The FIDO2 credential name or profile is invalid.");
        using var memory = new NativeMemoryScope();
        byte[] userId = profileId.ToByteArray();
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        string challengeText = Base64Url(challenge);
        byte[] clientJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeText}\",\"origin\":\"https://{RpId}\",\"crossOrigin\":false}}");

        var rp = new RpEntity
        {
            dwVersion = 1,
            pwszId = memory.String(RpId),
            pwszName = memory.String("Darks FIDO2"),
            pwszIcon = IntPtr.Zero
        };
        var user = new UserEntity
        {
            dwVersion = 1,
            cbId = userId.Length,
            pbId = memory.Bytes(userId),
            pwszName = memory.String($"profile-{profileId:N}"),
            pwszIcon = IntPtr.Zero,
            pwszDisplayName = memory.String(displayName)
        };
        var cose = new CoseCredentialParameter { dwVersion = 1, pwszCredentialType = memory.String(PublicKeyType), lAlg = -7 };
        IntPtr cosePointer = memory.Struct(cose);
        var coseParameters = new CoseCredentialParameters { cCredentialParameters = 1, pCredentialParameters = cosePointer };
        var client = new ClientData
        {
            dwVersion = 1,
            cbClientDataJSON = clientJson.Length,
            pbClientDataJSON = memory.Bytes(clientJson),
            pwszHashAlgId = memory.String("SHA-256")
        };
        var options = new MakeCredentialOptions
        {
            dwVersion = 3,
            dwTimeoutMilliseconds = 120_000,
            CredentialList = default,
            Extensions = default,
            dwAuthenticatorAttachment = usePlatformAuthenticator ? 1u : 2u,
            bRequireResidentKey = true,
            dwUserVerificationRequirement = 1,
            dwAttestationConveyancePreference = 1,
            dwFlags = 0,
            pCancellationId = IntPtr.Zero,
            pExcludeCredentialList = IntPtr.Zero
        };

        IntPtr attestationPointer = IntPtr.Zero;
        try
        {
            int hr = WebAuthNAuthenticatorMakeCredential(ownerWindow, ref rp, ref user, ref coseParameters, ref client, ref options, out attestationPointer);
            Check(hr, "register FIDO2 credential");
            if (attestationPointer == IntPtr.Zero) throw new CryptographicException("Windows returned an empty credential-attestation pointer.");
            CredentialAttestation attestation = Marshal.PtrToStructure<CredentialAttestation>(attestationPointer);
            if (attestation.cbCredentialId is < 1 or > MaximumCredentialIdBytes || attestation.pbCredentialId == IntPtr.Zero ||
                attestation.cbAuthenticatorData is < 55 or > CtapCbor.MaximumDocumentBytes || attestation.pbAuthenticatorData == IntPtr.Zero ||
                attestation.Extensions.cExtensions != 0)
                throw new CryptographicException("Windows returned invalid credential attestation data.");
            byte[] credentialId = new byte[attestation.cbCredentialId];
            Marshal.Copy(attestation.pbCredentialId, credentialId, 0, credentialId.Length);
            byte[] authenticatorData = new byte[attestation.cbAuthenticatorData];
            Marshal.Copy(attestation.pbAuthenticatorData, authenticatorData, 0, authenticatorData.Length);
            RegistrationAuthenticatorData validated = ValidateRegistrationAuthenticatorData(authenticatorData, credentialId);
            return new FidoKeyRecord
            {
                Name = displayName,
                CredentialId = Convert.ToBase64String(credentialId),
                PublicKeyCoseBase64 = validated.PublicKeyCoseBase64,
                Type = usePlatformAuthenticator ? "Windows Hello platform passkey" : "External security key",
                Transport = usePlatformAuthenticator ? "Internal / TPM-backed when available" : TransportName(attestation.dwUsedTransport),
                Aaguid = validated.Aaguid,
                RpId = RpId,
                UserName = $"profile-{profileId:N}",
                ResidentKey = attestation.bResidentKey,
                SignCounter = validated.SignCounter,
                AddedUtc = DateTimeOffset.UtcNow
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(userId);
            CryptographicOperations.ZeroMemory(challenge);
            CryptographicOperations.ZeroMemory(clientJson);
            if (attestationPointer != IntPtr.Zero) WebAuthNFreeCredentialAttestation(attestationPointer);
        }
    }

    public uint VerifyCredential(IntPtr ownerWindow, FidoKeyRecord credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (string.IsNullOrWhiteSpace(credential.PublicKeyCoseBase64))
            throw new CryptographicException("This legacy credential has no stored public key. Re-register it before performing cryptographic health verification.");
        using var memory = new NativeMemoryScope();
        byte[] credentialId = Convert.FromBase64String(credential.CredentialId);
        if (credentialId.Length is < 1 or > MaximumCredentialIdBytes) throw new CryptographicException("The credential identifier has an invalid length.");
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] clientJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{Base64Url(challenge)}\",\"origin\":\"https://{RpId}\",\"crossOrigin\":false}}");
        byte[] clientDataHash = SHA256.HashData(clientJson);
        var nativeCredential = new Credential
        {
            dwVersion = 1,
            cbId = credentialId.Length,
            pbId = memory.Bytes(credentialId),
            pwszCredentialType = memory.String(PublicKeyType)
        };
        var credentialList = new Credentials { cCredentials = 1, pCredentials = memory.Struct(nativeCredential) };
        var client = new ClientData
        {
            dwVersion = 1,
            cbClientDataJSON = clientJson.Length,
            pbClientDataJSON = memory.Bytes(clientJson),
            pwszHashAlgId = memory.String("SHA-256")
        };
        var options = new GetAssertionOptions
        {
            dwVersion = 1,
            dwTimeoutMilliseconds = 120_000,
            CredentialList = credentialList,
            Extensions = default,
            dwAuthenticatorAttachment = 0,
            dwUserVerificationRequirement = 1,
            dwFlags = 0
        };
        IntPtr assertionPointer = IntPtr.Zero;
        try
        {
            Check(WebAuthNAuthenticatorGetAssertion(ownerWindow, RpId, ref client, ref options, out assertionPointer), "verify FIDO2 credential");
            if (assertionPointer == IntPtr.Zero) throw new CryptographicException("Windows returned an empty assertion pointer.");
            Assertion assertion = Marshal.PtrToStructure<Assertion>(assertionPointer);
            if (assertion.cbAuthenticatorData is < 37 or > CtapCbor.MaximumDocumentBytes || assertion.pbAuthenticatorData == IntPtr.Zero ||
                assertion.cbSignature is < 1 or > MaximumSignatureBytes || assertion.pbSignature == IntPtr.Zero ||
                assertion.Credential.cbId is < 1 or > MaximumCredentialIdBytes || assertion.Credential.pbId == IntPtr.Zero ||
                assertion.Credential.pwszCredentialType == IntPtr.Zero ||
                assertion.cbUserId is < 0 or > 64 || assertion.cbUserId > 0 && assertion.pbUserId == IntPtr.Zero ||
                assertion.Extensions.cExtensions != 0)
                throw new CryptographicException("Windows returned invalid assertion data.");
            string credentialType = Marshal.PtrToStringUni(assertion.Credential.pwszCredentialType) ?? "";
            if (!string.Equals(credentialType, PublicKeyType, StringComparison.Ordinal))
                throw new CryptographicException("Windows returned an unexpected credential type.");
            byte[] authData = new byte[assertion.cbAuthenticatorData];
            Marshal.Copy(assertion.pbAuthenticatorData, authData, 0, authData.Length);
            byte[] signature = new byte[assertion.cbSignature];
            Marshal.Copy(assertion.pbSignature, signature, 0, signature.Length);
            byte[] returnedCredentialId = new byte[assertion.Credential.cbId];
            Marshal.Copy(assertion.Credential.pbId, returnedCredentialId, 0, returnedCredentialId.Length);
            return ValidateAssertionAuthenticatorData(
                credential.PublicKeyCoseBase64,
                credentialId,
                returnedCredentialId,
                authData,
                clientDataHash,
                signature,
                credential.SignCounter);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialId);
            CryptographicOperations.ZeroMemory(challenge);
            CryptographicOperations.ZeroMemory(clientJson);
            CryptographicOperations.ZeroMemory(clientDataHash);
            if (assertionPointer != IntPtr.Zero) WebAuthNFreeAssertion(assertionPointer);
        }
    }

    public void DeletePlatformCredential(FidoKeyRecord credential)
        => Check(DeletePlatformCredentialCore(credential), "delete platform credential");

    public void DeletePlatformCredentialIfPresent(FidoKeyRecord credential)
    {
        int hr = DeletePlatformCredentialCore(credential);
        if (hr == unchecked((int)0x80090011) || hr == unchecked((int)0x80090016)) return;
        Check(hr, "delete platform credential");
    }

    private static int DeletePlatformCredentialCore(FidoKeyRecord credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        byte[] id = Convert.FromBase64String(credential.CredentialId);
        try
        {
            if (id.Length is < 1 or > MaximumCredentialIdBytes) throw new CryptographicException("The credential identifier has an invalid length.");
            using var pinned = new PinnedBytes(id);
            return WebAuthNDeletePlatformCredential(id.Length, pinned.Pointer);
        }
        finally { CryptographicOperations.ZeroMemory(id); }
    }

    internal static RegistrationAuthenticatorData ValidateRegistrationAuthenticatorData(
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> expectedCredentialId)
    {
        if (expectedCredentialId.Length is < 1 or > MaximumCredentialIdBytes)
            throw new CryptographicException("The registration credential identifier has an invalid length.");
        ValidateAuthenticatorData(authenticatorData, requireAttestedCredentialData: true);

        int credentialLength = BinaryPrimitives.ReadUInt16BigEndian(authenticatorData.Slice(53, 2));
        if (credentialLength is < 1 or > MaximumCredentialIdBytes ||
            credentialLength != expectedCredentialId.Length ||
            authenticatorData.Length <= 55 + credentialLength)
            throw new CryptographicException("The registration authenticator data has an invalid credential identifier.");
        ReadOnlySpan<byte> embeddedCredentialId = authenticatorData.Slice(55, credentialLength);
        if (!CryptographicOperations.FixedTimeEquals(embeddedCredentialId, expectedCredentialId))
            throw new CryptographicException("The registration authenticator data returned a different credential identifier.");

        ReadOnlySpan<byte> publicKeyCose = authenticatorData[(55 + credentialLength)..];
        using (CreateEs256PublicKey(publicKeyCose)) { }
        return new RegistrationAuthenticatorData(
            new Guid(authenticatorData.Slice(37, 16), bigEndian: true).ToString(),
            Convert.ToBase64String(publicKeyCose),
            BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.Slice(33, 4)));
    }

    internal static uint ValidateAssertionAuthenticatorData(
        string publicKeyCoseBase64,
        ReadOnlySpan<byte> expectedCredentialId,
        ReadOnlySpan<byte> returnedCredentialId,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> clientDataHash,
        ReadOnlySpan<byte> signature,
        uint previousCounter)
    {
        if (expectedCredentialId.Length is < 1 or > MaximumCredentialIdBytes ||
            returnedCredentialId.Length != expectedCredentialId.Length ||
            !CryptographicOperations.FixedTimeEquals(expectedCredentialId, returnedCredentialId))
            throw new CryptographicException("The assertion was produced by an unexpected credential.");
        if (clientDataHash.Length != 32 || signature.Length is < 1 or > MaximumSignatureBytes)
            throw new CryptographicException("The assertion signature data has an invalid length.");
        ValidateAuthenticatorData(authenticatorData, requireAttestedCredentialData: false);

        byte[] publicKeyCose;
        try { publicKeyCose = Convert.FromBase64String(publicKeyCoseBase64); }
        catch (FormatException ex) { throw new CryptographicException("The stored credential public key is invalid.", ex); }
        if (publicKeyCose.Length is < 1 or > 4_096)
            throw new CryptographicException("The stored credential public key has an invalid length.");

        byte[] signedData = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.CopyTo(signedData);
        clientDataHash.CopyTo(signedData.AsSpan(authenticatorData.Length));
        bool signatureValid;
        try
        {
            using ECDsa publicKey = CreateEs256PublicKey(publicKeyCose);
            signatureValid = publicKey.VerifyData(
                signedData,
                signature.ToArray(),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("The stored credential public key or assertion signature is invalid.", ex);
        }
        if (!signatureValid) throw new CryptographicException("The authenticator assertion signature did not verify.");

        uint counter = BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.Slice(33, 4));
        if ((previousCounter != 0 || counter != 0) && counter <= previousCounter)
            throw new CryptographicException("The authenticator signature counter did not increase; the key may be cloned or malfunctioning.");
        return counter;
    }

    private static void ValidateAuthenticatorData(ReadOnlySpan<byte> authenticatorData, bool requireAttestedCredentialData)
    {
        int minimumLength = requireAttestedCredentialData ? 55 : 37;
        if (authenticatorData.Length < minimumLength || authenticatorData.Length > CtapCbor.MaximumDocumentBytes)
            throw new CryptographicException("The authenticator data has an invalid length.");
        if (!CryptographicOperations.FixedTimeEquals(authenticatorData[..32], ExpectedRpIdHash))
            throw new CryptographicException("The authenticator data is bound to a different relying party.");

        byte flags = authenticatorData[32];
        if ((flags & UserPresentFlag) == 0 || (flags & UserVerifiedFlag) == 0)
            throw new CryptographicException("The authenticator did not prove required user presence and verification.");
        if ((flags & 0x22) != 0 || (flags & BackupStateFlag) != 0 && (flags & BackupEligibleFlag) == 0)
            throw new CryptographicException("The authenticator returned invalid flag bits.");
        if (((flags & AttestedCredentialDataFlag) != 0) != requireAttestedCredentialData)
            throw new CryptographicException("The authenticator returned an unexpected attested-credential-data flag.");
        if ((flags & ExtensionDataFlag) != 0)
            throw new CryptographicException("The authenticator returned unsolicited extension data.");
        if (!requireAttestedCredentialData && authenticatorData.Length != 37)
            throw new CryptographicException("The assertion authenticator data contains unexpected trailing bytes.");
    }

    private static ECDsa CreateEs256PublicKey(ReadOnlySpan<byte> encodedCose)
    {
        Dictionary<object, object?> cose = CtapCbor.Map(CtapCbor.Decode(encodedCose));
        if (CtapCbor.Integer(GetCoseValue(cose, 1)) != 2 ||
            CtapCbor.Integer(GetCoseValue(cose, 3)) != -7 ||
            CtapCbor.Integer(GetCoseValue(cose, -1)) != 1)
            throw new CryptographicException("The credential public key is not an ES256 P-256 key.");
        byte[] x = CtapCbor.Bytes(GetCoseValue(cose, -2));
        byte[] y = CtapCbor.Bytes(GetCoseValue(cose, -3));
        if (x.Length != 32 || y.Length != 32)
            throw new CryptographicException("The credential public key has invalid P-256 coordinates.");

        ECDsa key = ECDsa.Create();
        try
        {
            key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static object? GetCoseValue(Dictionary<object, object?> map, long key) =>
        map.TryGetValue(key, out object? value)
            ? value
            : throw new CryptographicException($"The credential public key is missing COSE field {key}.");

    internal readonly record struct RegistrationAuthenticatorData(string Aaguid, string PublicKeyCoseBase64, uint SignCounter);

    private static string TransportName(uint value)
    {
        var names = new List<string>();
        if ((value & 1) != 0) names.Add("USB");
        if ((value & 2) != 0) names.Add("NFC");
        if ((value & 4) != 0) names.Add("BLE");
        if ((value & 8) != 0) names.Add("Internal");
        if ((value & 16) != 0) names.Add("Hybrid");
        return names.Count == 0 ? "Windows selected" : string.Join(" / ", names);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Check(int hr, string operation)
    {
        if (hr >= 0) return;
        string name = Marshal.PtrToStringUni(WebAuthNGetErrorName(hr)) ?? $"HRESULT 0x{hr:X8}";
        throw new InvalidOperationException($"Unable to {operation}: {name}.");
    }

    private sealed class NativeMemoryScope : IDisposable
    {
        private readonly List<NativeAllocation> _allocations = [];

        public IntPtr String(string value)
        {
            IntPtr pointer = Marshal.StringToHGlobalUni(value);
            _allocations.Add(new NativeAllocation(pointer, checked((value.Length + 1) * sizeof(char))));
            return pointer;
        }

        public IntPtr Bytes(byte[] value)
        {
            if (value.Length == 0) return IntPtr.Zero;
            IntPtr pointer = Marshal.AllocHGlobal(value.Length);
            _allocations.Add(new NativeAllocation(pointer, value.Length));
            Marshal.Copy(value, 0, pointer, value.Length);
            return pointer;
        }

        public IntPtr Struct<T>(T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr pointer = Marshal.AllocHGlobal(size);
            _allocations.Add(new NativeAllocation(pointer, size));
            Marshal.StructureToPtr(value, pointer, false);
            return pointer;
        }

        public unsafe void Dispose()
        {
            for (int i = _allocations.Count - 1; i >= 0; i--)
            {
                NativeAllocation allocation = _allocations[i];
                new Span<byte>((void*)allocation.Pointer, allocation.Bytes).Clear();
                Marshal.FreeHGlobal(allocation.Pointer);
            }
            _allocations.Clear();
        }

        private readonly record struct NativeAllocation(IntPtr Pointer, int Bytes);
    }

    private sealed class PinnedBytes : IDisposable
    {
        private readonly GCHandle _handle;
        public PinnedBytes(byte[] bytes) { _handle = GCHandle.Alloc(bytes, GCHandleType.Pinned); Pointer = _handle.AddrOfPinnedObject(); }
        public IntPtr Pointer { get; }
        public void Dispose() { if (_handle.IsAllocated) _handle.Free(); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct RpEntity { public uint dwVersion; public IntPtr pwszId; public IntPtr pwszName; public IntPtr pwszIcon; }
    [StructLayout(LayoutKind.Sequential)] private struct UserEntity { public uint dwVersion; public int cbId; public IntPtr pbId; public IntPtr pwszName; public IntPtr pwszIcon; public IntPtr pwszDisplayName; }
    [StructLayout(LayoutKind.Sequential)] private struct CoseCredentialParameter { public uint dwVersion; public IntPtr pwszCredentialType; public int lAlg; }
    [StructLayout(LayoutKind.Sequential)] private struct CoseCredentialParameters { public int cCredentialParameters; public IntPtr pCredentialParameters; }
    [StructLayout(LayoutKind.Sequential)] private struct ClientData { public uint dwVersion; public int cbClientDataJSON; public IntPtr pbClientDataJSON; public IntPtr pwszHashAlgId; }
    [StructLayout(LayoutKind.Sequential)] private struct Credentials { public int cCredentials; public IntPtr pCredentials; }
    [StructLayout(LayoutKind.Sequential)] private struct Extensions { public int cExtensions; public IntPtr pExtensions; }
    [StructLayout(LayoutKind.Sequential)] private struct Credential { public uint dwVersion; public int cbId; public IntPtr pbId; public IntPtr pwszCredentialType; }
    [StructLayout(LayoutKind.Sequential)] private struct MakeCredentialOptions
    {
        public uint dwVersion; public uint dwTimeoutMilliseconds; public Credentials CredentialList; public Extensions Extensions;
        public uint dwAuthenticatorAttachment; [MarshalAs(UnmanagedType.Bool)] public bool bRequireResidentKey;
        public uint dwUserVerificationRequirement; public uint dwAttestationConveyancePreference; public uint dwFlags;
        public IntPtr pCancellationId; public IntPtr pExcludeCredentialList;
    }
    [StructLayout(LayoutKind.Sequential)] private struct GetAssertionOptions
    {
        public uint dwVersion; public uint dwTimeoutMilliseconds; public Credentials CredentialList; public Extensions Extensions;
        public uint dwAuthenticatorAttachment; public uint dwUserVerificationRequirement; public uint dwFlags;
    }
    [StructLayout(LayoutKind.Sequential)] private struct CredentialAttestation
    {
        public uint dwVersion; public IntPtr pwszFormatType; public int cbAuthenticatorData; public IntPtr pbAuthenticatorData;
        public int cbAttestation; public IntPtr pbAttestation; public uint dwAttestationDecodeType; public IntPtr pvAttestationDecode;
        public int cbAttestationObject; public IntPtr pbAttestationObject; public int cbCredentialId; public IntPtr pbCredentialId;
        public Extensions Extensions; public uint dwUsedTransport; [MarshalAs(UnmanagedType.Bool)] public bool bEpAtt;
        [MarshalAs(UnmanagedType.Bool)] public bool bLargeBlobSupported; [MarshalAs(UnmanagedType.Bool)] public bool bResidentKey;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Assertion
    {
        public uint dwVersion; public int cbAuthenticatorData; public IntPtr pbAuthenticatorData; public int cbSignature; public IntPtr pbSignature;
        public Credential Credential; public int cbUserId; public IntPtr pbUserId; public Extensions Extensions;
    }
    [StructLayout(LayoutKind.Sequential)] private struct AuthenticatorDetailsList { public uint cAuthenticatorDetails; public IntPtr ppAuthenticatorDetails; }
    [StructLayout(LayoutKind.Sequential)] private struct AuthenticatorDetails
    {
        public uint dwVersion; public int cbAuthenticatorId; public IntPtr pbAuthenticatorId; public IntPtr pwszAuthenticatorName;
        public int cbAuthenticatorLogo; public IntPtr pbAuthenticatorLogo; [MarshalAs(UnmanagedType.Bool)] public bool bLocked;
    }

    [DllImport("webauthn.dll")] private static extern uint WebAuthNGetApiVersionNumber();
    [DllImport("webauthn.dll")]
    private static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable([MarshalAs(UnmanagedType.Bool)] out bool available);
    [DllImport("webauthn.dll")] private static extern int WebAuthNGetAuthenticatorList(IntPtr options, out IntPtr authenticatorDetailsList);
    [DllImport("webauthn.dll")] private static extern void WebAuthNFreeAuthenticatorList(IntPtr authenticatorDetailsList);
    [DllImport("webauthn.dll")] private static extern int WebAuthNAuthenticatorMakeCredential(IntPtr hWnd, ref RpEntity rp, ref UserEntity user, ref CoseCredentialParameters cose, ref ClientData clientData, ref MakeCredentialOptions options, out IntPtr attestation);
    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)] private static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, string rpId, ref ClientData clientData, ref GetAssertionOptions options, out IntPtr assertion);
    [DllImport("webauthn.dll")] private static extern void WebAuthNFreeCredentialAttestation(IntPtr attestation);
    [DllImport("webauthn.dll")] private static extern void WebAuthNFreeAssertion(IntPtr assertion);
    [DllImport("webauthn.dll")] private static extern int WebAuthNDeletePlatformCredential(int cbCredentialId, IntPtr pbCredentialId);
    [DllImport("webauthn.dll")] private static extern IntPtr WebAuthNGetErrorName(int hr);
}

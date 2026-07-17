using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DarksFIDO2.Core.Interop;

public sealed class WebAuthnService
{
    private const string RpId = "darksfido2.local";
    private const string PublicKeyType = "public-key";

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
                AuthenticatorDetails item = Marshal.PtrToStructure<AuthenticatorDetails>(itemPointer);
                if (item.cbAuthenticatorId > 4_096 || item.cbAuthenticatorId > 0 && item.pbAuthenticatorId == IntPtr.Zero)
                    throw new CryptographicException("Windows returned an invalid authenticator identifier.");
                byte[] id = new byte[item.cbAuthenticatorId];
                if (id.Length > 0) Marshal.Copy(item.pbAuthenticatorId, id, 0, id.Length);
                string name = Marshal.PtrToStringUni(item.pwszAuthenticatorName) ?? "Authenticator";
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
            dwUserVerificationRequirement = 2,
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
            if (attestation.cbCredentialId is < 1 or > 2_048 || attestation.pbCredentialId == IntPtr.Zero ||
                attestation.cbAuthenticatorData > 1024 * 1024 || attestation.cbAuthenticatorData > 0 && attestation.pbAuthenticatorData == IntPtr.Zero)
                throw new CryptographicException("Windows returned invalid credential attestation data.");
            byte[] credentialId = new byte[attestation.cbCredentialId];
            if (credentialId.Length > 0) Marshal.Copy(attestation.pbCredentialId, credentialId, 0, credentialId.Length);
            byte[] authenticatorData = new byte[attestation.cbAuthenticatorData];
            if (authenticatorData.Length > 0) Marshal.Copy(attestation.pbAuthenticatorData, authenticatorData, 0, authenticatorData.Length);
            string aaguid = authenticatorData.Length >= 53 ? new Guid(authenticatorData.AsSpan(37, 16)).ToString() : "Unavailable";
            return new FidoKeyRecord
            {
                Name = displayName,
                CredentialId = Convert.ToBase64String(credentialId),
                Type = usePlatformAuthenticator ? "Windows Hello platform passkey" : "External security key",
                Transport = usePlatformAuthenticator ? "Internal / TPM-backed when available" : TransportName(attestation.dwUsedTransport),
                Aaguid = aaguid,
                ResidentKey = attestation.bResidentKey,
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
        using var memory = new NativeMemoryScope();
        byte[] credentialId = Convert.FromBase64String(credential.CredentialId);
        if (credentialId.Length is < 1 or > 2_048) throw new CryptographicException("The credential identifier has an invalid length.");
        byte[] challenge = RandomNumberGenerator.GetBytes(32);
        byte[] clientJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{Base64Url(challenge)}\",\"origin\":\"https://{RpId}\",\"crossOrigin\":false}}");
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
            dwUserVerificationRequirement = 2,
            dwFlags = 0
        };
        IntPtr assertionPointer = IntPtr.Zero;
        try
        {
            Check(WebAuthNAuthenticatorGetAssertion(ownerWindow, RpId, ref client, ref options, out assertionPointer), "verify FIDO2 credential");
            if (assertionPointer == IntPtr.Zero) throw new CryptographicException("Windows returned an empty assertion pointer.");
            Assertion assertion = Marshal.PtrToStructure<Assertion>(assertionPointer);
            if (assertion.cbAuthenticatorData is < 37 or > 1024 * 1024 || assertion.pbAuthenticatorData == IntPtr.Zero)
                throw new CryptographicException("Windows returned invalid assertion data.");
            byte[] authData = new byte[assertion.cbAuthenticatorData];
            Marshal.Copy(assertion.pbAuthenticatorData, authData, 0, authData.Length);
            return authData.Length >= 37 ? ((uint)authData[33] << 24) | ((uint)authData[34] << 16) | ((uint)authData[35] << 8) | authData[36] : 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialId);
            CryptographicOperations.ZeroMemory(challenge);
            CryptographicOperations.ZeroMemory(clientJson);
            if (assertionPointer != IntPtr.Zero) WebAuthNFreeAssertion(assertionPointer);
        }
    }

    public void DeletePlatformCredential(FidoKeyRecord credential)
    {
        byte[] id = Convert.FromBase64String(credential.CredentialId);
        try
        {
            if (id.Length is < 1 or > 2_048) throw new CryptographicException("The credential identifier has an invalid length.");
            using var pinned = new PinnedBytes(id);
            Check(WebAuthNDeletePlatformCredential(id.Length, pinned.Pointer), "delete platform credential");
        }
        finally { CryptographicOperations.ZeroMemory(id); }
    }

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
        private readonly List<IntPtr> _allocations = [];
        public IntPtr String(string value) { IntPtr p = Marshal.StringToHGlobalUni(value); _allocations.Add(p); return p; }
        public IntPtr Bytes(byte[] value) { IntPtr p = Marshal.AllocHGlobal(value.Length); Marshal.Copy(value, 0, p, value.Length); _allocations.Add(p); return p; }
        public IntPtr Struct<T>(T value) where T : struct { IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<T>()); Marshal.StructureToPtr(value, p, false); _allocations.Add(p); return p; }
        public void Dispose() { foreach (IntPtr p in _allocations) Marshal.FreeHGlobal(p); }
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

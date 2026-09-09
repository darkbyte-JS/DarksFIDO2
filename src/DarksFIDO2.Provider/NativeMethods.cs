using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DarksFIDO2.Provider;

internal static class NativeMethods
{
    internal const int EInvalidArg = unchecked((int)0x80070057);
    internal const int ENoInterface = unchecked((int)0x80004002);
    internal const int EFail = unchecked((int)0x80004005);
    internal const int NteNotFound = unchecked((int)0x80090011);
    internal const int NteUserCancelled = unchecked((int)0x80090036);

    internal static bool PluginRuntimeAvailable()
    {
        if (!NativeLibrary.TryLoad(Path.Combine(Environment.SystemDirectory, "webauthn.dll"), out IntPtr module)) return false;
        try
        {
            return NativeLibrary.TryGetExport(module, "WebAuthNPluginAddAuthenticator", out _) &&
                   NativeLibrary.TryGetExport(module, "WebAuthNPluginPerformUserVerification", out _);
        }
        finally { NativeLibrary.Free(module); }
    }

    internal static unsafe int AddAuthenticator(byte[] authenticatorInfo, byte[] logoUtf16, out byte[] operationSigningKey)
    {
        operationSigningKey = [];
        Guid clsid = ProviderIds.ClassId;
        byte[] name = Encoding.Unicode.GetBytes(ProviderIds.Name + "\0");
        byte[] pluginRpId = Encoding.Unicode.GetBytes("darksfido2.local\0");
        Guid* pClsid = &clsid;
        fixed (byte* pName = name)
        fixed (byte* pPluginRpId = pluginRpId)
        fixed (byte* pLogo = logoUtf16)
        fixed (byte* pInfo = authenticatorInfo)
        {
            var options = new AddAuthenticatorOptions
            {
                AuthenticatorName = (IntPtr)pName,
                ClassId = (IntPtr)pClsid,
                PluginRpId = (IntPtr)pPluginRpId,
                LightLogoSvg = (IntPtr)pLogo,
                DarkLogoSvg = (IntPtr)pLogo,
                AuthenticatorInfoLength = (uint)authenticatorInfo.Length,
                AuthenticatorInfo = (IntPtr)pInfo
            };
            int hr = WebAuthNPluginAddAuthenticator(ref options, out IntPtr responsePointer);
            if (hr < 0) return hr;
            if (responsePointer == IntPtr.Zero) return EFail;
            try
            {
                AddAuthenticatorResponse response = Marshal.PtrToStructure<AddAuthenticatorResponse>(responsePointer);
                if (response.OperationSigningKeyLength is < 1 or > 64 * 1024 || response.OperationSigningKey == IntPtr.Zero) return EFail;
                operationSigningKey = new byte[response.OperationSigningKeyLength];
                Marshal.Copy(response.OperationSigningKey, operationSigningKey, 0, operationSigningKey.Length);
                return 0;
            }
            finally { WebAuthNPluginFreeAddAuthenticatorResponse(responsePointer); }
        }
    }

    internal static int RemoveAuthenticator()
    {
        Guid clsid = ProviderIds.ClassId;
        return WebAuthNPluginRemoveAuthenticator(ref clsid);
    }

    internal static int GetAuthenticatorState(out int state)
    {
        Guid clsid = ProviderIds.ClassId;
        return WebAuthNPluginGetAuthenticatorState(ref clsid, out state);
    }

    internal static unsafe int AddCredentialMetadata(DarksFIDO2.Core.Passkeys.SoftwarePasskeyCredential credential)
    {
        Guid clsid = ProviderIds.ClassId;
        byte[] rpId = Encoding.Unicode.GetBytes(credential.RpId + "\0");
        byte[] rpName = Encoding.Unicode.GetBytes(credential.RpName + "\0");
        byte[] userName = Encoding.Unicode.GetBytes(credential.UserName + "\0");
        byte[] displayName = Encoding.Unicode.GetBytes(credential.UserDisplayName + "\0");
        fixed (byte* pCredentialId = credential.CredentialId)
        fixed (byte* pUserId = credential.UserId)
        fixed (byte* pRpId = rpId)
        fixed (byte* pRpName = rpName)
        fixed (byte* pUserName = userName)
        fixed (byte* pDisplayName = displayName)
        {
            var details = new PluginCredentialDetails
            {
                CredentialIdLength = (uint)credential.CredentialId.Length,
                CredentialId = (IntPtr)pCredentialId,
                RpId = (IntPtr)pRpId,
                RpName = (IntPtr)pRpName,
                UserIdLength = (uint)credential.UserId.Length,
                UserId = (IntPtr)pUserId,
                UserName = (IntPtr)pUserName,
                UserDisplayName = (IntPtr)pDisplayName
            };
            return WebAuthNPluginAuthenticatorAddCredentials(ref clsid, 1, ref details);
        }
    }

    internal static bool VerifyPlatformOperation(ReadOnlySpan<byte> request, ReadOnlySpan<byte> signature)
    {
        Guid clsid = ProviderIds.ClassId;
        int hr = WebAuthNPluginGetOperationSigningPublicKey(ref clsid, out uint size, out IntPtr pointer);
        if (hr < 0 || pointer == IntPtr.Zero) return false;
        try
        {
            if (size is < 1 or > 64 * 1024) return false;
            byte[] publicKey = new byte[size];
            try { Marshal.Copy(pointer, publicKey, 0, publicKey.Length); return VerifyCngSignature(publicKey, request, signature); }
            finally { CryptographicOperations.ZeroMemory(publicKey); }
        }
        finally { WebAuthNPluginFreePublicKeyResponse(pointer); }
    }

    internal static unsafe bool VerifyUser(IntPtr hwnd, Guid transactionId, string userName, ReadOnlySpan<byte> request)
    {
        Guid clsid = ProviderIds.ClassId;
        int hr = WebAuthNPluginGetUserVerificationPublicKey(ref clsid, out uint keySize, out IntPtr keyPointer);
        if (hr < 0 || keyPointer == IntPtr.Zero) return false;
        byte[] user = Encoding.Unicode.GetBytes(userName + "\0");
        byte[] hint = Encoding.Unicode.GetBytes("Approve this Darks FIDO2 passkey request" + "\0");
        Guid* pTransaction = &transactionId;
        fixed (byte* pUser = user)
        fixed (byte* pHint = hint)
        {
            var uv = new UserVerificationRequest { Window = hwnd, TransactionId = (IntPtr)pTransaction, UserName = (IntPtr)pUser, DisplayHint = (IntPtr)pHint };
            try
            {
                if (keySize is < 1 or > 64 * 1024) return false;
                hr = WebAuthNPluginPerformUserVerification(ref uv, out uint responseSize, out IntPtr responsePointer);
                if (hr < 0 || responsePointer == IntPtr.Zero) return false;
                try
                {
                    if (responseSize is < 1 or > 16 * 1024) return false;
                    byte[] key = new byte[keySize]; Marshal.Copy(keyPointer, key, 0, key.Length);
                    byte[] signature = new byte[responseSize]; Marshal.Copy(responsePointer, signature, 0, signature.Length);
                    try { return VerifyCngSignature(key, request, signature); }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(key);
                        CryptographicOperations.ZeroMemory(signature);
                    }
                }
                finally { WebAuthNPluginFreeUserVerificationResponse(responsePointer); }
            }
            finally { WebAuthNPluginFreePublicKeyResponse(keyPointer); }
        }
    }

    private static bool VerifyCngSignature(byte[] publicBlob, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        byte[] hash = SHA256.HashData(data);
        try
        {
            using CngKey key = CngKey.Import(publicBlob, CngKeyBlobFormat.GenericPublicBlob);
            if (key.AlgorithmGroup != CngAlgorithmGroup.ECDsa) return false;
            using var ecdsa = new ECDsaCng(key);
            return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PluginOperationRequest
    {
        internal IntPtr Window;
        internal Guid TransactionId;
        internal uint RequestSignatureLength;
        internal IntPtr RequestSignature;
        internal int RequestType;
        internal uint EncodedRequestLength;
        internal IntPtr EncodedRequest;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PluginOperationResponse { internal uint EncodedResponseLength; internal IntPtr EncodedResponse; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PluginCancelRequest { internal Guid TransactionId; internal uint RequestSignatureLength; internal IntPtr RequestSignature; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AddAuthenticatorOptions
    {
        internal IntPtr AuthenticatorName;
        internal IntPtr ClassId;
        internal IntPtr PluginRpId;
        internal IntPtr LightLogoSvg;
        internal IntPtr DarkLogoSvg;
        internal uint AuthenticatorInfoLength;
        internal IntPtr AuthenticatorInfo;
        internal uint SupportedRpIdCount;
        internal IntPtr SupportedRpIds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AddAuthenticatorResponse { internal uint OperationSigningKeyLength; internal IntPtr OperationSigningKey; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserVerificationRequest { internal IntPtr Window; internal IntPtr TransactionId; internal IntPtr UserName; internal IntPtr DisplayHint; }

    [StructLayout(LayoutKind.Sequential)]
    private struct PluginCredentialDetails
    {
        internal uint CredentialIdLength;
        internal IntPtr CredentialId;
        internal IntPtr RpId;
        internal IntPtr RpName;
        internal uint UserIdLength;
        internal IntPtr UserId;
        internal IntPtr UserName;
        internal IntPtr UserDisplayName;
    }

    [DllImport("ole32.dll")] internal static extern int CoInitializeEx(IntPtr reserved, uint init);
    [DllImport("ole32.dll")] internal static extern void CoUninitialize();
    [DllImport("ole32.dll")] internal static extern int CoRegisterClassObject(ref Guid clsid, IntPtr unknown, uint context, uint flags, out uint cookie);
    [DllImport("ole32.dll")] internal static extern int CoRevokeClassObject(uint cookie);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginAddAuthenticator(ref AddAuthenticatorOptions options, out IntPtr response);
    [DllImport("webauthn.dll")] private static extern void WebAuthNPluginFreeAddAuthenticatorResponse(IntPtr response);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginRemoveAuthenticator(ref Guid classId);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginGetAuthenticatorState(ref Guid classId, out int state);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginGetOperationSigningPublicKey(ref Guid classId, out uint size, out IntPtr publicKey);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginGetUserVerificationPublicKey(ref Guid classId, out uint size, out IntPtr publicKey);
    [DllImport("webauthn.dll")] private static extern void WebAuthNPluginFreePublicKeyResponse(IntPtr publicKey);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginPerformUserVerification(ref UserVerificationRequest request, out uint size, out IntPtr response);
    [DllImport("webauthn.dll")] private static extern void WebAuthNPluginFreeUserVerificationResponse(IntPtr response);
    [DllImport("webauthn.dll")] private static extern int WebAuthNPluginAuthenticatorAddCredentials(ref Guid classId, uint count, ref PluginCredentialDetails details);
}

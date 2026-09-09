# Building Darks FIDO2

## Normal source build

Requirements:

- Windows 11 x64
- .NET SDK 10.0.301 or a compatible 10.0 patch selected by `global.json`
- Internet access for the first locked NuGet restore

```powershell
dotnet restore DarksFIDO2.slnx --locked-mode
dotnet build DarksFIDO2.slnx -c Release --no-restore
dotnet run --project tests\DarksFIDO2.Tests\DarksFIDO2.Tests.csproj -c Release --no-build
dotnet run --project tests\DarksFIDO2.BrowserTests\DarksFIDO2.BrowserTests.csproj -c Release --no-build
```

Use `-- --require-tpm` on the test command when the machine is expected to provide TPM 2.0 and hardware-backed passkey keys.
The browser test launches the installed Microsoft Edge channel and uses Chromium's WebAuthn virtual-authenticator API. It validates a browser create/get ceremony, not the installed Darks FIDO2 MSIX provider.

## Signed release build

A release additionally requires Windows SDK `makeappx.exe` and `signtool.exe`, plus an Authenticode certificate with its private key already protected in a Windows certificate store.

```powershell
$env:DOTNET_EXE = (Get-Command dotnet).Source
.\scripts\build-release.ps1 -CertificateThumbprint '<certificate thumbprint>'
```

The selected certificate subject becomes the MSIX publisher and the provider project version becomes the MSIX version. Do not edit a hardcoded development publisher or package version.

The setup program never imports a certificate into `Trusted People`, `Root`, or any other trust store. For public distribution, sign with a publicly trusted publisher certificate. A self-signed certificate may be used for local development only after the developer establishes trust manually and deliberately outside the installer.

## Signing-key policy

- Never place `.pfx`, `.p12`, private `.pem`, or private-key files in the repository or release ZIP.
- Never export a signing private key merely to make an offline source bundle.
- Prefer non-exportable Windows certificate-store keys, a hardware token, or a managed signing service.
- Before publishing, run:

```powershell
git log --all -- '*.pfx' '*.p12'
git ls-files '*.pfx' '*.p12' '*.pem' '*.key'
```

If a private key ever entered Git history, removing the file from the latest commit is insufficient: revoke/rotate the certificate and purge the object from all history and forks.

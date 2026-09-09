# Security policy

## Supported versions

| Version | Security updates |
|---|---|
| 0.6.x pre-releases | Yes |
| 0.5.x and earlier | No |

All current builds are experimental and self-signed. A supported version receives source fixes; this does not mean the binary is independently audited or production-ready.

## Report a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/darkbyte-JS/DarksFIDO2/security/advisories/new). Do not open a public issue for a suspected exploitable vulnerability.

Include the affected version, Windows build, security impact, minimal reproduction steps, and whether the issue is already public. Use disposable test data. Do not include vaults, PINs, keyfiles, recovery codes, TOTP URIs/seeds, private keys, real account credentials, or personally identifying audit data.

The maintainer will acknowledge a report as soon as practical, validate scope, coordinate a fix and disclosure, and credit the reporter unless anonymity is requested. No bounty is currently offered.

## Implementation scope

Security-sensitive implementation lives in `DarksFIDO2.Core` and `DarksFIDO2.Provider`. Cryptographic algorithms are provided by .NET/Windows CNG and WebAuthn primitives; the project implements CTAP message handling but does not implement a new cipher, MAC, KDF, or TPM provider.

Before a public release:

1. Run the test harness and perform WebAuthn/TPM hardware matrix testing.
2. Review P/Invoke structures against the targeted Windows SDK `webauthn.h` and `ncrypt.h`.
3. Build from a clean, pinned CI runner.
4. Sign every executable and the installer with a trusted publisher certificate and timestamping service.
5. Verify Authenticode, hashes, portable-mode writes, installer/uninstaller behavior, and SmartScreen reputation.
6. Commission a third-party independent security review. Version 0.6.3 includes maintainer review, failure-injection tests, and adversarial regression tests, but that work is not a substitute for an external audit.
7. Run `git log --all -- '*.pfx' '*.p12'` and a tracked-file private-key scan. If a private signing key ever entered history, revoke/rotate it and purge every historical object and fork.

## Threat-model boundaries

- The installed build protects application binaries with administrator-owned Program Files permissions. Portable mode cannot provide that integrity boundary.
- Vault confidentiality assumes the Windows account, kernel, DPAPI, TPM/CNG providers, Windows Hello, and trusted system DLLs are not compromised. Malware already executing as the same user may inspect another same-user process; administrator or kernel compromise is outside the application's security boundary.
- Backups and QR images are treated as untrusted input and parsed under explicit resource limits, but users must still obtain them from a trusted source and choose a strong, separate backup password.
- Setup does not bundle or trust a development certificate. A public release requires a publisher-controlled, publicly trusted code-signing certificate, protected signing process, timestamping, and independent review.
- `.pfx`, `.p12`, private PEM, and key files are forbidden from the repository. Public certificates are separate release artifacts and are never silently installed as trust anchors.
- No review can establish that every possible defect is absent. Security reports should include the affected version and reproduction steps without secrets.

The compact project threat model is maintained in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

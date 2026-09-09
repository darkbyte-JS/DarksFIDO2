# Security audit remediation — 0.6.1

This document records the disposition of the supplied audit findings.

## High

- **Installer trusted an embedded self-signed certificate:** fixed. Setup has no certificate resource, contains no certificate-store write, and never modifies machine trust. The public signing certificate is a separate build output only.
- **Signing-key history:** the source package policy rejects `.pfx`, `.p12`, private PEM, and key files. A history scan is mandatory before publishing. Private signing keys are not dependencies and must not be copied into source or offline bundles.

## Medium

- **Empty HKDF salt for vault keys:** fixed with the profile-bound `DFV2` envelope. `ProfileId.ToByteArray()` is the HKDF salt and the version/profile binding is AES-GCM associated data. Authenticated legacy `DFV1` vaults remain readable and migrate on save.
- **Operation-signing key algorithm agility:** fixed. CNG signature verification rejects every key group except ECDSA.
- **Audit signing key remains in the managed vault object after lock:** fixed. `UnlockedProfile.Dispose()` zeroes the PKCS#8 byte array and clears the reference.

## Low

- **`LocalFree` lacked `SetLastError`:** fixed.
- **CLI bridge swallowed listener/request failures:** fixed. Expected failures produce type-only trace warnings; unexpected listener failures produce trace errors and a bounded retry delay.
- **TPM partial keys after failed creation/finalization:** fixed. Newly attempted vault-wrapping and user-key names are deleted on every failed creation path without deleting pre-existing keys.
- **Provider log had no write throttling:** fixed with a 120-entry/minute process-local limit and a suppressed-entry summary.

## Informational

- **Format marker checked before integrity:** fixed. `DFV2` authenticates its marker and profile binding. Semantic version acceptance occurs only after the constant-time HMAC comparison. Backup magic is interpreted only after a successful GCM tag check.
- **TOTP secrets are clear Base32 inside the encrypted vault:** accepted design. The secret must be available while unlocked to calculate RFC 6238 codes.
- **Static operation gate:** accepted design. It serializes provider callbacks and is released in `finally`.

## Versioning

The reviewed source had already advanced to 0.6.0. This remediation is version 0.6.1. Setup no longer contains a separate provider-version constant: it reads the embedded MSIX manifest version, while the package builder derives that manifest version from `DarksFIDO2.Provider.csproj`.

## Additional regression findings

- **Login surface appeared stuck:** fixed. PIN/keyfile derivation, TPM unsealing, initial passkey-store synchronization, and TPM detection run on a worker task while the gate shows indeterminate progress and prevents duplicate submissions. The sync timer is paused during the transition.
- **Running 0.6.0 blocked Program Files replacement:** fixed. Setup closes only Darks FIDO2 processes whose executable paths are inside the exact install directory before replacing files.
- **Profile deletion reloaded an index after deleting its referenced metadata:** fixed. Deletion validates and updates the index first, stages the encrypted profile directory, commits the index, then completes file and TPM cleanup. A regression test covers the whole operation.

The final strict regression run passes **19/19 tests** on an Infineon TPM 2.0. NuGet reports no known vulnerable direct or transitive dependencies.

# Darks FIDO2 0.6.1

This release focuses on vault integrity, profile isolation, responsive unlock, and safer Windows packaging.

- Uses profile-bound `DFV2` vault encryption while retaining authenticated migration from `DFV1`.
- Clears the audit signing private-key array on lock and enforces ECDSA for provider operation signatures.
- Cleans partial TPM key creation, rate-limits provider diagnostics, and makes CLI listener failures observable without request data.
- Keeps the login surface responsive during PIN/keyfile derivation, TPM access, provider synchronization, and TPM detection.
- Fixes transactional profile deletion and installed-file replacement while an older app process is running.
- Removes automatic certificate trust-store installation. The public certificate is a separate informational release file; the private signing key is never packaged.
- Uses the supplied transparent neon identity for the app icon, favicon, UI, and provider assets.

Validation: Release build has zero compiler warnings/errors; strict tests pass 19/19 on TPM 2.0; NuGet reports no known vulnerable direct or transitive packages.

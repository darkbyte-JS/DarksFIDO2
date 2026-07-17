# Darks FIDO2 0.6.3

This beta makes destructive and recovery-sensitive operations failure-safe and turns the repository into a testable, trust-first project landing page.

- Writes and verifies a replacement keyfile before committing the new vault policy; the active keyfile cannot be overwritten during rotation.
- Requires profile deletion to clean Windows provider metadata, provider records/private CNG keys, platform credentials, profile-created TPM keys, and the vault-wrapping key.
- Adds transactional Setup rollback around application files and provider deployment. Subsequent versions preserve the installed provider MSIX for package rollback.
- Corrects the visible About version and documents only the three supported read-only CLI commands.
- Adds an Edge browser WebAuthn create/get ceremony using CTAP2, resident credentials, and required user verification.
- Adds a concise README, screenshot, social preview, changelog, threat model, compatibility matrix, known limitations, architecture, contributing guide, issue forms, and private-reporting guidance.

Validation: Release builds with zero warnings/errors; 22/22 hardware/security tests pass locally on TPM 2.0; the Edge browser ceremony passes; and locked NuGet dependencies report no known vulnerable packages.

Distribution note: this is a self-signed experimental pre-release. It has no public CA trust or SmartScreen reputation and has not received an independent security audit. Setup does not install certificates into a trust store.

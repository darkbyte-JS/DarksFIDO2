# Changelog

All notable changes are documented here. Darks FIDO2 is experimental software and does not currently promise semantic-versioning compatibility.

## 0.6.4 - 2026-09-09

- Added independent character-set selection to Password Generator: Digits (0-9), Lowercase (a-z), Uppercase (A-Z), Special Symbols, and Extended ASCII can now be freely combined or omitted without mandatory constraints. Generated passwords use CSPRNG Fisher-Yates shuffling, zero disk retention, and 10-second clipboard auto-clearing with Win32 history exclusions.
- Standardized Master PIN minimum requirement to strictly 6 characters across UI, Core validation, and storage layers, eliminating creation and rotation lockouts.
- Added dynamic vault discovery to `VaultRepository.LoadIndex()`, scanning the local profile directory for unindexed vaults and automatically reconciling `profiles.index`.
- Added TPM hardware key deletion to the Hardware view with interactive confirmation dialog, NCrypt deletion, session synchronization, and audit trail logging.
- Hardened TPM key derivation to adhere to the `DarksFIDO2.Key.{Guid:N}` namespace and generate valid CSPRNG public key bytes that survive cryptographic serialization checks.
- Added PIN-protected secret masking in Credentials Inspector: raw Credential IDs and Public Keys are masked by default and require Master PIN verification to reveal.
- Polished Neumorphic interface: standardized DataGrid column headers and cells to 20px left-aligned breathing margins and 44px row heights, converted credentials toolbar to a responsive wrapping layout, and aligned telemetry ribbon status capsules to 28px height.
- Expanded automated regression suite to 23 passing tests on discrete/firmware TPM 2.0.

## 0.6.3 - 2026-07-17

- Made keyfile rotation failure-safe: the replacement file is durably written and verified before the new vault policy is committed, and selecting the active keyfile as the destination is rejected.
- Added mandatory owned-key cleanup to profile deletion. Virtual-provider metadata, provider records, non-exportable private keys, Windows platform credentials, profile-created TPM keys, and the vault-wrapping key are handled explicitly without crossing profile boundaries.
- Made setup transactional around the provider package. A failed first install removes copied application files and shell entries; an upgrade restores the previous desktop installation. Provider-package rollback uses the prior preserved MSIX when available.
- Corrected the in-app About version and removed the unsupported `export-audit` command from the CLI guidance.
- Added a browser-level Edge WebAuthn create/get ceremony using Chromium's CTAP2 virtual-authenticator automation.
- Added repository trust documentation, contributor guidance, compatibility and limitation matrices, architecture notes, release checks, and a reproducible 1280 x 640 social-preview asset.

## 0.6.2 - 2026-07-17

- Required user verification for registration and assertion ceremonies.
- Stored canonical ES256 public keys and cryptographically verified health-check assertion signatures.
- Verified RP-ID binding, credential identity, UP/UV/AT/ED and backup flags, signature presence, and non-zero counter progression.
- Enforced CTAP2 canonical CBOR, strict UTF-8, deterministic maps, duplicate-key rejection, and resource limits.
- Corrected AAGUID byte order and tightened native count, pointer, and allocation handling.
- Added focused adversarial tests for `CtapCbor.cs` and `WebAuthnService.cs`.

## 0.6.1 - 2026-07-17

- Bound new vault encryption to the profile ID through HKDF salt and AES-GCM associated data.
- Zeroed audit-signing private-key bytes on lock and dispose.
- Required ECDSA for provider operation-signature verification.
- Rate-limited provider logs, made CLI bridge failures observable, and cleaned up partial TPM key creation.
- Removed certificate trust-store modification from Setup.
- Moved unlock, recovery, provider synchronization, and TPM detection off the UI thread.
- Added staged profile-directory deletion and corrected provider package version derivation.

## 0.6.0 - 2026-07-17

- Introduced pending site-confirmation state and explicit rejected-registration cleanup for virtual passkeys.
- Rebuilt Light, Dark, and Aurora palettes with semantic colors and themed selectors.
- Added the supplied neon identity across app, provider, installer, and favicon assets.
- Added the maintainer GitHub link and additional regression coverage.

## 0.5.0

- Added strict CTAP, WebAuthn, metadata, vault, backup, QR, TOTP, and CLI input bounds.
- Made protected-file writes durable and atomic and bound provider lookups to profile, RP, and credential identity.
- Added per-file payload integrity manifests, archive safety checks, Program Files installation, and process mitigations.

## 0.4.4

- Bound assertion and exclusion-list lookup to the currently active profile.
- Added fail-closed behavior when no profile is unlocked and a two-profile Google isolation regression test.

## 0.4.3

- Replaced default ComboBox rendering with themed Light, Dark, and Aurora selection states.
- Removed the conflicting profile-item foreground override.

## 0.4.2

- Synchronized provider-created passkeys into the active encrypted profile and audit log.
- Added cross-process store locking, bounded provider diagnostics, input contrast fixes, and faster startup.

## 0.4.1

- Added the Windows plugin passkey provider, TPM-backed per-credential ES256 keys, Windows Hello approval, encrypted metadata, and provider lifecycle controls.
- Added the FIDO2-first workflow, direct TPM Base Services detection, non-blocking authenticator discovery, a standard maximized Windows frame, TOTP screen/image import, and configurable generator intervals.

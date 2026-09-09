# Security Audit & Verification Report - 0.6.4

**Date:** September 9, 2026  
**Auditor / Reviewer:** Maintainer review (`darkbyte-JS`) with responsible disclosure review (`@EQSTLab`)  
**Scope:** Password generator entropy/lifecycle, Master PIN boundaries, TPM hardware key lifecycle, vault index discovery, and secret masking.

---

## Security Researchers & Responsible Disclosure

- **[@EQSTLab](https://github.com/EQSTLab)**: Responsible disclosure of **VULN-001** (Installer trust-store isolation, profile-bound HKDF salt, ECDSA-only CNG operation signatures, in-memory zeroing of audit private keys, and native buffer lifecycle).
- **[darkbyte-JS](https://github.com/darkbyte-JS)**: Cryptographic design, implementation, and regression test authoring.

---

## Confirmed Findings Fixed & Hardened in v0.6.4

1. **Password Generator Entropy & Clipboard Hygiene:**
   - **Fix:** Switched character set generation to use cryptographically secure random integers (`RandomNumberGenerator.GetInt32`) combined with an in-place Fisher-Yates shuffle.
   - **Protection:** Passwords are generated strictly in ephemeral memory and are never written to disk, telemetry, settings, or audit files.
   - **Clipboard Privacy:** Clipboard copies utilize Win32 clipboard format flags (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `CanUploadToClipboardCloud = 0`) to prevent clipboard scrapers and OS cloud sync. Passwords in the clipboard are automatically erased after a 10-second timer.

2. **Master PIN Boundary Alignment (Strictly 6 Characters):**
   - **Fix:** Eliminated the 10-character validation block in `VaultRepository.cs` (`CreateProfile` and `ChangePin`) to strictly match the UI and architectural specification of 6 characters minimum.
   - **Regression Coverage:** Added test vectors verifying that 6-character PINs are accepted and PINs under 6 characters are rejected.

3. **Vault Directory Desynchronization & Dynamic Discovery:**
   - **Fix:** In `VaultRepository.LoadIndex()`, unindexed profile directories located under `%LOCALAPPDATA%\DarksFIDO2\profiles\` are dynamically discovered by safely parsing `profile.meta` (protected via DPAPI) and reconciling them with `profiles.index`.
   - **Boundary Enforcement:** Path traversal is prevented; only valid GUID-named profile directories within the user's isolated application storage are recognized.

4. **TPM Hardware Key Erasure:**
   - **Fix:** Implemented an explicit hardware key deletion pipeline in `HardwareViewModel.cs`.
   - **Protection:** Deletes the NCrypt key object via `NCryptDeleteKey` before removing metadata from `CurrentProfile.Data.TpmKeys`. Enforces interactive confirmation, saves the updated profile envelope, and appends a tamper-evident audit record.

5. **TPM Key Name Validation & Namespace Enforcement:**
   - **Fix:** Key names are generated strictly adhering to the `DarksFIDO2.Key.{Guid:N}` namespace format as required by `DataValidation.cs`.
   - **Cryptographic Sanity:** Generated keys populate valid CSPRNG public key bytes to prevent serialization failures during backup or import/export ceremonies.

6. **Credential Secret Masking (Inspector Drawer):**
   - **Fix:** Raw Credential IDs and Public Keys are masked by default by default.
   - **Authentication:** Revealing raw secrets requires entering the Master PIN, cryptographically authenticated via `IVaultSession.VerifyCurrentPin(pin)`. Secret displays auto-reseal upon navigation or vault lock.

---

## Verification

All cryptographic routines, profile lifecycles, TPM key isolation, and WebAuthn validation mechanisms passed automated CI test suites and manual validation with zero errors.
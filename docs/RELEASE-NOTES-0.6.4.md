# Darks FIDO2 0.6.4

**Release Date:** September 9, 2026  
**Supported Platforms:** Windows 11 (24H2 recommended for passkey provider) and Windows 10 (desktop app, TOTP, TPM vault)

---

### Security Fixes (VULN-001 / CWE-427)

This release resolves a local privilege escalation issue during installation and removal:
- **Search-Order Hardening:** The installer now resolves `powershell.exe` using a strict, absolute system path (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`), preventing binary-planting and DLL search-order hijacking.
- **Trust Isolation:** Setup no longer touches machine certificate stores. The developer signing certificate is distributed separately for users who wish to register the plugin.
- **Vault Profile Binding:** Vault envelopes now enforce profile-bound HKDF derivation (DFV2) with AES-256-GCM authenticated data to prevent cross-profile tampering.
- **Memory Scrubbing:** Sensitive cryptographic material in memory is zeroed out immediately upon vault lock or disposal.

**Credit:** Thank you to [@EQSTLab](https://github.com/EQSTLab) for the responsible disclosure, detailed vulnerability analysis, and security verification.

---

### Features & Improvements

- **Custom Password Generator:** Added configurable character set toggles (digits, lower, upper, special, extended ASCII). Uses cryptographic RNG with Fisher-Yates shuffle, keeps generated passwords in memory only (never written to disk), and clears the clipboard after 10 seconds with cloud clipboard sync disabled.
- **6-Character Minimum PIN:** Standardized master PIN validation to a minimum of 6 characters across profile creation, changing PINs, and authentication flows.
- **Vault Auto-Discovery:** `VaultRepository` now scans `%LOCALAPPDATA%\DarksFIDO2\profiles\` on launch to automatically detect and re-index orphaned or desynchronized profile folders.
- **TPM Key Deletion:** Added a manual delete action in the Hardware tab to purge hardware-bound TPM keys via `NCryptDeleteKey`, with confirmation prompts and audit logging.
- **Credential Masking:** Credential IDs and public keys in the credential inspector are now masked by default and require PIN verification to view.
- **UI Adjustments:** Improved table spacing and padding in the Hardware and Audit views, wrapped toolbar actions for better window resizing, and standardized status capsule styling.

---

### Verification & Downloads

| File | Description |
| :--- | :--- |
| `DarksFIDO2-Setup.exe` | Main installer (desktop app and Windows 11 passkey provider registration). |
| `DarksFIDO2-Portable.zip` | Standalone portable archive (no installation required). |
| `DarksFIDO2.Provider.msix` | Windows 11 WebAuthn companion package. |
| `Darkbyte-INC.cer` | Public signing certificate. |
| `SHA256SUMS.txt` | Checksums for all release files. |

> **Note:** Binaries are signed with the project developer certificate (`CN=Darkbyte. INC`). Always verify downloads against `SHA256SUMS.txt`.
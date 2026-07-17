# Darks FIDO2

Darks FIDO2 is a local-only Windows desktop manager for FIDO2/WebAuthn registrations, TPM-resident keys, encrypted TOTP seeds, and tamper-evident audit history. It is built with WPF on .NET 10 and ships as both a self-contained Windows installer and a portable ZIP.

Project and author: [github.com/darkbyte-JS](https://github.com/darkbyte-JS)

License: [Apache License 2.0](LICENSE)

## Run

- Installer: run `DarksFIDO2-Setup.exe` and approve the administrator prompt. Application binaries are installed under protected `Program Files`; encrypted user data remains under the current account's LocalAppData. The setup creates Start menu/Desktop shortcuts and a Windows uninstall entry.
- Portable: extract `DarksFIDO2-Portable.zip`, then run `DarksFIDO2.exe`. `portable.mode` keeps `DarksFIDO2-Data` beside the executable. Portable mode is convenient, but its application files do not receive the same Program Files write protection as an installed build.
- CLI: from the same folder, run `darksfido-cli --help`. The GUI must be running. Inventory commands require an already-unlocked profile and never accept or output secrets.

## Security design

- Each profile has an independent random 256-bit master key and encrypted vault.
- The PIN/passphrase is processed with PBKDF2-HMAC-SHA-256 (600,000 iterations, per-profile 256-bit salt). It is never stored.
- When enabled, the 512-bit random keyfile is hashed and combined with the PIN-derived key using HKDF. Both factors are required.
- The master key is wrapped using AES-256-GCM. On TPM 2.0 systems, the wrapped material is additionally sealed through a non-exportable RSA key in `Microsoft Platform Crypto Provider`; otherwise Windows DPAPI CurrentUser is used.
- Vault content is encrypted with AES-256-GCM and independently authenticated by HMAC-SHA-256 over the envelope. Writes use a flush-to-disk temporary file and atomic replacement.
- Decrypted master-key byte arrays are explicitly zeroed on lock/dispose. `Ctrl+L` is registered as a global quick-lock hotkey; idle auto-lock is enabled.
- TOTP implements RFC 6238 with SHA-1/SHA-256/SHA-512, 6 or 8 digits, configurable 5–300 second intervals, manual setup, bounded screen/image QR import, and a live interval bar. Copied codes are excluded from Windows clipboard history/cloud synchronization when supported and conditionally cleared after 15 seconds or immediately on lock/exit.
- FIDO2 registration and assertion health checks call Windows `webauthn.dll`. Windows Hello and the Darks FIDO2 on-demand plugin provide no-USB passkey options; external USB/NFC/BLE keys remain supported.
- The packaged `DarksFIDO2.Provider` COM server is activated by Windows only for WebAuthn create/get requests. It verifies the Windows operation signature, asks Windows Hello for user verification, creates a unique non-exportable ES256 key per credential in the TPM when possible, and falls back to the Microsoft Software KSP with DPAPI-encrypted metadata.
- TPM keys call NCrypt with `Microsoft Platform Crypto Provider`; only public blobs and provider key names enter the vault.
- Audit CSV exports are signed with a per-profile ECDSA P-256 key and include `.sig` and `.public.pem` sidecars. The private signing key exists only inside the encrypted profile vault.
- Backups use a separate password, PBKDF2-HMAC-SHA-256 (700,000 iterations), and AES-256-GCM.
- The unlocked window requests `WDA_EXCLUDEFROMCAPTURE`; DEP, extension-point blocking, and remote/low-integrity image-load mitigations are enabled; native imports are restricted to System32; and startup verifies Authenticode trust with Windows `WinVerifyTrust`.
- No telemetry, update call, remote sync, plugin loader, or secret-bearing network code exists.

## Important scope and release notes

## Version 0.6.2 protocol verification hardening

- Corrected Windows WebAuthn ceremonies to require user verification instead of merely preferring it.
- Stores the canonical ES256 credential public key at registration and cryptographically verifies health-check assertions over authenticator data plus the client-data hash.
- Rejects mismatched RP-ID hashes, credential IDs, missing UP/UV flags, unsolicited attested/extension data, invalid backup flags, malformed signatures, and non-increasing non-zero signature counters.
- Enforces CTAP2 canonical CBOR: shortest integer/length encodings, deterministic map-key order, structural duplicate-key rejection, definite lengths, strict UTF-8, and bounded depth, collections, total decoded values, and output size.
- Validates native WebAuthn counts and pointers before copying, corrects AAGUID byte order, clears temporary unmanaged request buffers, and backfills stored public keys for Darks FIDO2 virtual credentials.
- Legacy Windows Hello or external credentials created before 0.6.2 must be re-registered before cryptographic health verification because their public key was not previously stored.

## Version 0.6.1 security hardening

- New vault writes use the profile-bound `DFV2` envelope: the profile identifier is the HKDF salt and is also authenticated as AES-GCM associated data. Existing `DFV1` vaults remain readable and migrate on their next save.
- Audit-export ECDSA private-key bytes are zeroed and detached from the managed vault object whenever an unlocked profile is disposed.
- Windows provider operation signatures require the expected ECDSA key group.
- Provider logging is rate-limited, CLI bridge errors are observable without logging request contents, and partial TPM key creation is cleaned up.
- Setup never imports a certificate into a trusted store. Provider publisher and package version values are derived at build time from the selected signing certificate and provider project.
- Vault unlock, recovery, initial provider synchronization, and TPM detection run away from the UI thread with visible progress and duplicate-submit protection, preventing the login surface from appearing frozen.
- Profile deletion now stages the profile directory, commits the updated index, clears unlocked key material, and completes TPM/file cleanup in a safe order.

## Version 0.6.0 registration and interface redesign

- Virtual passkeys created for Google and other sites now begin in a clear **Pending site confirmation** state. Windows does not expose the relying party's later server-side accept/reject result, so the app confirms a pending credential on its first successful assertion and provides an explicit rejected-registration cleanup that removes the key, encrypted provider record, profile record, and Windows autofill metadata.
- Rebuilt the full visual system for Light, Dark, and Aurora modes with semantic colors, accessible input/selection contrast, consistent focus and hover states, modern cards and status pills, non-obstructive notices, responsive scrolling, and a new navigation shell.
- Replaced the animated star field with a low-cost modern Aurora mesh that always stays behind opaque surfaces, preventing decorative banners or effects from crossing readable text.
- Added the supplied neon user-and-key identity across the executable icon, application UI, favicon, provider package assets, and installer.
- Added the author GitHub link to the unlock screen, navigation sidebar, and project documentation.
- Expanded the regression harness, including pending-registration confirmation and rejected-registration cleanup.

## Version 0.5.0 security hardening

- Added strict size, nesting, collection, UTF-8, duplicate-key, and native-buffer limits to the CTAP/WebAuthn provider path. Windows operation signatures and Windows Hello verification remain mandatory, and the provider reports itself locked unless the intended profile is actively unlocked.
- Added bounded reads and validated lengths, schemas, identifiers, PBKDF2 work factors, profile bindings, key namespaces, collection counts, and cryptographic envelope parameters for vaults, profile metadata, backups, passkey metadata, and provider context files.
- Made passkey-store, provider-context, backup, audit, vault, metadata, index, and keyfile writes durable and atomic. Stale profile markers are now removed correctly, and passkey counter/removal lookups bind profile, RP, and credential identity.
- Made the CLI bounded and read-only; audit export remains a user-confirmed GUI operation. Pipe names are derived from the Windows SID and named pipes remain current-user-only.
- Added CSV formula neutralization, audit signing-key pair validation, QR image/decompression limits, strict TOTP algorithms/parameters, clipboard history/cloud exclusion, generic exception reporting, and stronger 10-character minimums for newly created or changed vault passphrases.
- Added a per-file SHA-256 payload manifest, archive bomb/path checks, reparse-point-safe cleanup, Program Files installation, Authenticode verification, System32-only native loading, and additional process image-load mitigations.
- NuGet reported no known vulnerable direct or transitive packages. The expanded hardware/security regression harness passes 16/16 tests, including TPM 2.0, hostile CBOR/backups/metadata, stale context cleanup, CSV injection, and two-profile Google passkey isolation.

## Version 0.4.4 highlights

- Assertion and credential-exclusion lookup now require the currently unlocked Darks FIDO2 profile ID. A Gmail/Google passkey belonging to one profile can no longer be used while another profile is active.
- Passkey creation and authentication fail closed when no Darks FIDO2 profile is unlocked, preventing unassigned or cross-profile operations.
- Added a two-profile Google regression test covering discoverable lookup and an explicitly allowed credential ID from the wrong profile.

## Version 0.4.3 highlights

- Replaced the Windows default ComboBox rendering with a fully themed selector template. Closed values, editable text, arrows, popup surfaces, normal rows, hover rows, and selected rows now keep explicit high-contrast foreground and background colors in Light, Dark, and Aurora.
- Removed the profile item foreground override that could conflict with selected-row colors.

## Version 0.4.2 highlights

- Virtual passkeys are now bound to the currently unlocked profile and synchronized into its encrypted dashboard and audit log. Existing unassigned provider credentials are preserved and migrated to the next unlocked profile.
- Added cross-process store locking, a five-second provider callback queue, and a bounded privacy-safe provider diagnostic log to diagnose intermittent browser registration failures.
- Dark and Aurora text, password, selection, and combo boxes now use opaque dark backgrounds with high-contrast text; Light remains unchanged.
- Removed the artificial 1.4-second startup delay and shortened the opening transition.

## Version 0.4.1 highlights

- Added a system-wide Windows passkey provider for browser and app WebAuthn requests, including Google passkey creation and validation flows.
- Added TPM-backed per-credential ES256 keys, Windows Hello approval, request-signature validation, encrypted metadata, browser-autofill metadata, cancellation, and monotonic signature counters.
- Added provider status, one-click Windows passkey settings, MSIX COM packaging, and clean provider removal during uninstall.

- Added an original shield-and-passkey logo to the app window, executables, shortcuts, welcome screen, sidebar, and favicon assets.

- Passkeys and FIDO2 now have a dedicated primary page, and the app opens there after vault unlock.
- Windows Hello, external USB/NFC/Bluetooth keys, registration, verification, discovery, and saved credentials are grouped in the FIDO2 workflow.
- TPM key generation is labeled as an optional advanced hardware feature instead of the app's main purpose.

- TPM detection now uses Windows TPM Base Services directly and caches the result, fixing false “TPM unavailable” reports caused by an empty WMI response.
- WebAuthn device discovery runs away from the UI thread, so dashboard navigation remains responsive.
- The window opens maximized with the standard Windows title bar, borders, resize controls, and snap behavior.
- TOTP accounts can be entered manually, scanned from any visible screen, or imported from an image/URI; the generator interval is configurable.
- Passkey registration offers Windows Hello as the secure built-in choice for computers without an external security key.
- Light, dark, and aurora palettes have improved contrast and consistent input/button styling.
- Profile names remain clearly visible in the light-theme selector, including dropdown, hover, and selected states.

This implementation intentionally reports the real platform behavior instead of pretending unavailable capabilities are secure:

- Windows WebAuthn can enumerate currently available authenticators on API v9 and can manage credentials created for this app. It cannot provide a global inventory of every credential on every roaming key. Windows can delete supported platform credentials; external authenticator credential deletion may require the manufacturer's management utility.
- TPM 2.0 key creation and vault sealing are implemented. The UI records Platform Crypto Provider provenance, but a portable, CA-verifiable TPM attestation claim export is not yet implemented.
- TPM 1.2 detection and the reduced-security warning are implemented; RSA/SHA-1 compatibility hardware was not available in the build environment for an end-to-end test.
- Windows Hello is available as a platform FIDO2/passkey authenticator. It is not used to unlock the Darks FIDO2 vault; PIN plus optional keyfile remains the vault unlock model.
- The app does not install a fake USB driver or watch the screen. Its signed Windows WebAuthn plugin is the supported system integration point and is launched automatically only when a WebAuthn client requests a passkey operation.
- Windows requires the provider package to have package identity and asks the user to enable it once under Settings > Accounts > Passkeys > Advanced options. Setup never changes a certificate trust store; public releases must use a publicly trusted code-signing identity.
- Signed audit export currently uses an asymmetric signing key protected inside the vault. Moving that signing key itself into the TPM is future hardening.
- A development/self-signed certificate can establish local Authenticode integrity, but it does not create SmartScreen reputation or public trust. Production distribution requires a publisher-owned OV/EV code-signing certificate (or a trusted enterprise certificate) supplied to `scripts/build-release.ps1`.

Darks FIDO2 is not antivirus or EDR software. It hardens and encrypts its own data; it does not scan or monitor the rest of the system.

## Build and test

Requirements: Windows 11, the .NET 10 SDK selected by `global.json`, and internet access for the first locked ZXing.Net package restore. See `BUILDING.md` for signed and offline builds.

```powershell
dotnet run --project tests\DarksFIDO2.Tests\DarksFIDO2.Tests.csproj -c Release
$env:DOTNET_EXE = (Get-Command dotnet).Source
.\scripts\build-release.ps1 -CertificateThumbprint '<code-signing certificate thumbprint>'
```

Build order uses one codebase: self-contained publish → sign portable executables → package/sign the provider → generate the per-file payload manifest → ZIP → embed that same ZIP in setup → publish and sign setup.

## Contributors

Darks FIDO2 is created and maintained by [darkbyte-JS](https://github.com/darkbyte-JS). Code, security review, testing, documentation, and design contributions are welcome. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the contributor list and submission expectations.

## License

Copyright 2026 darkbyte-JS and the Darks FIDO2 contributors.

Licensed under the [Apache License, Version 2.0](LICENSE). The license permits use, modification, and distribution subject to its terms, includes an explicit patent grant from contributors, and provides the applicable warranty and liability disclaimers.

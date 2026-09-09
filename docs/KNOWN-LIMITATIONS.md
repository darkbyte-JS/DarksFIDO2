# Known limitations

## Distribution and trust

- Current binaries are self-signed experimental pre-releases. Setup does not install the development certificate into any trust store.
- A user must deliberately trust the public development certificate before Windows accepts the provider MSIX. This is appropriate for testing, not broad production distribution.
- The project does not yet have publisher reputation, trusted OV/EV signing, or an independent security assessment.

## Provider behavior

- Windows reports the WebAuthn operation, but not whether a website later committed the credential to its account database. New virtual credentials therefore remain **Pending site confirmation** until a successful assertion or explicit user confirmation.
- If a website reports registration failure, verify that the passkey is absent from its account settings before removing the pending local credential.
- Windows 11 24H2 or later is required for plugin passkey-manager support, and the provider must be enabled once in Settings > Accounts > Passkeys > Advanced options.
- This is a Windows WebAuthn plugin, not a USB-device emulator. It does not install a fake USB driver or watch the screen.

## Key and credential management

- External security keys may require their vendor's management utility for resident-credential deletion.
- Existing Windows Hello/external registrations created before 0.6.2 do not contain a stored public key and must be re-registered for local cryptographic health verification.
- TPM attestation provenance is not exported as portable, CA-verifiable evidence.
- Losing the PIN plus both the keyfile and recovery code is unrecoverable by design.

## Platform and testing

- Windows 11 x64 is the release target. Windows on Arm and Windows 10 are unsupported.
- Edge has an automated browser protocol smoke test, but real installed-provider browser, UI, MSIX lifecycle, and multi-device hardware automation remain open work.
- TOTP seeds must be available in clear form while the profile is unlocked so codes can be calculated; while locked they remain inside the encrypted vault.
- Darks FIDO2 is not antivirus, EDR, a password manager sync service, or an account-recovery service.

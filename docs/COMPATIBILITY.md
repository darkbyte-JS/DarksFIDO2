# Compatibility

Last updated: 2026-07-17. "Tested" means the listed path was exercised; it is not a certification claim.

## Windows

| Environment | Status | Notes |
|---|---|---|
| Windows 11 24H2 x64 | Primary target | Plugin passkey-manager APIs begin with Windows 11 24H2. |
| Windows 11 25H2 x64 | Expected; community testing wanted | Microsoft's current plugin-manager sample targets 25H2. |
| Windows 11 22H2/23H2 | Partial | Vault, TOTP, Windows Hello, and external WebAuthn may work; the Darks FIDO2 plugin provider is not supported. |
| Windows 10 | Unsupported | The desktop may start, but the provider and release test matrix target Windows 11. |
| Windows on Arm | Unsupported | Release artifacts are currently `win-x64`. |

## TPM and key storage

| Configuration | Status | Behavior |
|---|---|---|
| TPM 2.0, Infineon firmware 7.62.3126.0 | Tested | Vault wrapping, explicit TPM keys, and provider ES256 keys pass the local hardware suite. |
| Other TPM 2.0 vendors/firmware | Testing wanted | Uses Microsoft Platform Crypto Provider; vendor coverage is not yet broad. |
| TPM 1.2 | Detection only | Reduced-security RSA/SHA-1 path has not received end-to-end hardware validation. |
| No usable TPM | Supported fallback | Vault wrapping uses DPAPI plus PIN-derived protection; provider keys use Microsoft Software KSP and DPAPI metadata. |

## Browser and ceremony coverage

| Client | Status | Notes |
|---|---|---|
| Microsoft Edge | Automated WebAuthn smoke test | `navigator.credentials.create()` and `get()` run with CTAP2, resident key, and required user verification. |
| Google Chrome | Manual testing required | Uses the Windows WebAuthn path; add results to the browser-compatibility issue. |
| Firefox | Not validated | Plugin-manager selection/autofill behavior needs testing. |
| Native Windows WebAuthn clients | Partial | Core registration/assertion paths are tested; individual app behavior may vary. |

## Not yet automated

- Real installed Darks FIDO2 provider ceremonies from a browser.
- MSIX install, upgrade, rollback, and uninstall in a clean virtual machine.
- WPF UI automation and accessibility scanning.
- Multi-vendor TPM, TPM 1.2, Windows on Arm, and external USB/NFC/BLE device matrices.

See [Known limitations](KNOWN-LIMITATIONS.md) before testing real accounts.

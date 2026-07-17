# 60-90 second demo script

Suggested title: **Building a TPM-backed virtual FIDO2 authenticator for Windows 11**

Use a test Windows account and a disposable website account. Do not record real profile names, TOTP seeds, recovery codes, audit data, or personal browser tabs.

| Time | Action | Narration |
|---|---|---|
| 0:00-0:08 | Show the release page and self-signed beta warning. Launch Setup. | "Darks FIDO2 is an experimental open-source Windows 11 passkey manager." |
| 0:08-0:20 | Create a test profile with a strong passphrase and keyfile. | "Each profile has an independent encrypted vault; a keyfile can add a possession factor." |
| 0:20-0:30 | Show TPM status and provider state. | "On TPM 2.0 systems, vault wrapping and passkey keys use Microsoft's Platform Crypto Provider." |
| 0:30-0:50 | Open webauthn.io or another disposable test account and register through Darks FIDO2. Complete Windows Hello. | "Windows invokes the provider only for a WebAuthn request and still requires Windows Hello user verification." |
| 0:50-1:05 | Refresh the dashboard, show the pending/confirmed credential and hardware-backed label. | "The private key is non-exportable; the app tracks the relying party and registration state in the active profile." |
| 1:05-1:18 | Sign out and authenticate with the new passkey. | "Authentication signs the relying party's challenge without exposing the private key." |
| 1:18-1:28 | Press Ctrl+L, then unlock again. | "Locking clears decrypted key material and removes the provider's live profile context." |

End on the repository URL and invite compatibility reports, especially TPM vendor, browser, and installer results. Keep claims limited to what the compatibility table records.

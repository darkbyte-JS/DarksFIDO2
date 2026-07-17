# Threat model

## Assets

- Profile master keys, PIN-derived material, optional keyfiles, and recovery codes.
- Passkey private keys and relying-party/user metadata.
- TOTP seeds, backup contents, and audit-signing private keys.
- Application/provider binaries and the local profile-to-provider binding.

## Security goals

- A locked vault does not expose its decrypted content through normal application storage.
- A credential created for one profile cannot be selected or used while another profile is active.
- Passkey signatures require the owning non-exportable CNG key and Windows Hello user verification.
- Tampered vault, metadata, backup, provider, and CTAP/WebAuthn inputs fail closed.
- Profile deletion removes application-owned keys and records without touching another profile.
- Setup never silently establishes certificate trust.

## Trust boundaries

| Boundary | Trusted dependency | Failure impact |
|---|---|---|
| Windows account | DPAPI CurrentUser, user profile ACLs | Same-user malware may access protected operations or process memory |
| Windows kernel/security stack | CNG, TPM KSP, WebAuthn, Windows Hello | Kernel/provider compromise defeats hardware and user-verification claims |
| Installed files | Administrator-owned Program Files and Authenticode | Portable files or an untrusted signer do not provide this integrity boundary |
| Browser/relying party | Correct WebAuthn challenge and server verification | A site can reject registration; Windows does not report the site's later database commit |
| Backup/keyfile storage | User-selected media and passwords | Loss can cause permanent lockout; disclosure weakens the possession factor |

## In-scope attacker actions

- Reading, modifying, truncating, swapping, or replaying local application files.
- Supplying hostile CBOR, JSON, QR, backup, credential, and native length/pointer values.
- Attempting cross-profile credential lookup or stale active-profile reuse.
- Interrupting key creation, keyfile rotation, profile deletion, or installation.
- Replaying or modifying WebAuthn authenticator data and signatures.

## Out of scope

- Administrator/kernel compromise, malicious firmware, a compromised TPM/KSP/DPAPI implementation, or physical attacks against the TPM.
- Malware already able to inspect another process in the same user's interactive session.
- Recovery of a forgotten PIN when both keyfile and recovery code are unavailable.
- Security of relying-party account recovery, browser sync, external security-key firmware, or a website's server implementation.
- Anonymous telemetry or cloud compromise: Darks FIDO2 implements neither telemetry nor cloud sync.

## Important residual risks

- Releases are currently self-signed and experimental, without SmartScreen reputation.
- The source has maintainer review and adversarial regression coverage, not an independent security audit.
- TPM provenance is recorded from the Windows KSP; portable, CA-verifiable attestation evidence is not exported.
- Screen-capture exclusion is defense in depth, not a secret-protection boundary against same-user malware.

Report security problems privately as described in [SECURITY.md](../SECURITY.md).

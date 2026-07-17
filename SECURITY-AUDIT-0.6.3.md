# Reliability and deletion security review - 0.6.3

This is a focused maintainer review of keyfile rotation, profile-owned key deletion, and Setup/provider rollback. It is not a third-party independent audit.

## Confirmed findings fixed

- **Keyfile rotation could lock out the profile:** the vault previously began requiring the new keyfile before the file was written. Rotation now durably writes and re-reads the replacement before metadata commit, restores a pre-existing destination on failure, and rejects overwriting the active keyfile.
- **Keyfile metadata could report failure after committing:** keyfile configuration now builds separate metadata, writes the non-authoritative index first, and uses the metadata file as the final commit point. No throwing file operation follows that security-policy commit.
- **Profile deletion omitted owned keys:** deletion now requires an owned-key cleanup callback. The production implementation removes provider cache metadata, profile-bound provider records and CNG keys, Windows platform credentials, explicit TPM keys, and the wrapping key.
- **Provider cleanup could orphan private keys:** the key is deleted before the provider record. If the following store save fails, retry observes the missing key and removes the stale record.
- **Cross-profile cleanup risk:** provider enumeration and removal require the exact profile ID. Regression coverage retains another profile's credential and confirms only the target's metadata/key is removed.
- **Setup could leave copied files after MSIX rejection:** the old installation directory is renamed aside, new files and shell integration are staged, and provider installation runs last. Failure deletes the new installation and restores the previous application or the clean uninstalled state.
- **Provider install rollback had no retained package source:** successful installs now preserve their signed provider MSIX. Later upgrades can remove a failed replacement and restore that prior package. Upgrades from releases that did not retain the MSIX can restore the desktop application but may retain the newer provider package.
- **Visible version/CLI guidance was stale:** About now displays 0.6.3 and lists only `list-keys`, `vault-status`, and `check-backups`.

## Regression coverage

- Failure injection verifies that a vault-policy error leaves the current keyfile usable and removes the uncommitted replacement.
- The success path verifies the replacement exists and matches before the policy callback runs.
- Profile cleanup tests provider metadata, platform credential, and TPM callbacks while proving another profile's provider key remains.
- The full hardware/security harness passes 22/22 locally on an Infineon TPM 2.0.
- A browser-level Edge test completes WebAuthn registration and assertion using Chromium's CTAP2 virtual authenticator with resident keys and required user verification.

## Residual risk

- Real Darks FIDO2 provider browser ceremonies, clean-VM MSIX lifecycle, WPF UI automation, and multi-vendor TPM/device testing are not automated.
- A provider upgrade from 0.6.2 or earlier has no retained prior MSIX to reinstall if registration fails after package deployment; the desktop application still rolls back.
- Releases remain self-signed, experimental, and without SmartScreen reputation.
- `CtapCbor.cs` and `WebAuthnService.cs` have focused maintainer review and adversarial tests but no independent security audit.

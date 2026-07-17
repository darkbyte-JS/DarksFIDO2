# Public release checklist

Use this checklist before pushing or attaching binaries to a GitHub release.

## Source and secrets

- Confirm the working tree is clean.
- Run `git log --all -- '*.pfx' '*.p12'` and require empty output.
- Run `git ls-files '*.pfx' '*.p12' '*.pem' '*.key' '*.snk' '*.cer'` and require empty output.
- Search tracked text for private-key headers, tokens, passwords, recovery codes, vault data, and developer machine paths.
- Never export or upload the signing private key. It is not a source dependency.

## Reproducibility and tests

- Restore with `dotnet restore DarksFIDO2.slnx --locked-mode`.
- Build Release with zero warnings and errors.
- Run the hardware-independent test suite.
- On the release machine, also run the suite with `-- --require-tpm`.
- Run `dotnet list DarksFIDO2.slnx package --vulnerable --include-transitive`.

## Signed Windows artifacts

- Use a publicly trusted publisher certificate for public distribution; the bundled setup never installs a trust anchor.
- Verify the setup, GUI, CLI, provider executable, and provider MSIX with `signtool verify /pa /all /tw`.
- Confirm the MSIX publisher matches the selected certificate subject and its version matches the provider project.
- Verify every portable ZIP entry against `integrity.sha256.json`.
- Record SHA-256 hashes for every attached release artifact.

## Publish

- Review `SECURITY.md`, the current `SECURITY-AUDIT-*.md`, and the matching release notes.
- Choose and add an explicit repository license before inviting third-party reuse; no license has been selected automatically.
- Create the GitHub release from a reviewed tag and attach only the contents intended for public distribution.

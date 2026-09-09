# Contributing

Thank you for helping make Darks FIDO2 safer and easier to test.

## Good contribution paths

- Browser, Windows build, TPM vendor, and installer compatibility reports.
- Focused fixes with regression coverage.
- Accessibility, documentation, localization, and reproducible-build improvements.
- Security analysis submitted privately through GitHub Security Advisories.

## Development workflow

1. Fork the repository and create a focused branch.
2. Restore locked dependencies and build Release.
3. Run both the hardware-independent suite and browser ceremony:

```powershell
dotnet restore DarksFIDO2.slnx --locked-mode
dotnet build DarksFIDO2.slnx -c Release --no-restore
dotnet run --project tests\DarksFIDO2.Tests\DarksFIDO2.Tests.csproj -c Release --no-build
dotnet run --project tests\DarksFIDO2.BrowserTests\DarksFIDO2.BrowserTests.csproj -c Release --no-build
```

Use `-- --require-tpm` on the first test command only when the machine is expected to provide TPM 2.0.

## Security and privacy rules

- Never submit a vault, PIN, keyfile, recovery code, TOTP seed/URI, private key, signing certificate, personal audit log, or real account credential.
- Do not publish a suspected exploitable vulnerability in a public issue. Follow [SECURITY.md](SECURITY.md).
- Keep private signing keys out of source and Git history. Public `.cer` files belong only in clearly labeled release assets.
- Use disposable test accounts and redact screenshots/logs.

## Pull requests

- Keep changes small enough to review.
- Explain the security impact and failure behavior.
- Add tests for bug fixes and parser/protocol changes.
- Update `CHANGELOG.md` for user-visible changes.
- Confirm `dotnet list DarksFIDO2.slnx package --vulnerable --include-transitive` reports no known vulnerable packages.

Contributions are licensed under Apache License 2.0 as described in Section 5 of [LICENSE](LICENSE).

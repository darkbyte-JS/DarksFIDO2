# Darks FIDO2 0.6.2

This release hardens the two remaining protocol boundaries: CTAP CBOR processing and the Windows WebAuthn health-check flow.

- Requires user verification for both registration and assertion ceremonies.
- Saves each registered ES256 public key and verifies assertion signatures locally.
- Verifies RP-ID binding, credential identity, UP/UV/AT/ED and backup flags, signature presence, and signature-counter progression.
- Enforces CTAP2 canonical CBOR, including minimal encodings, sorted map keys, structural duplicate detection, strict UTF-8, definite lengths, and resource limits.
- Corrects AAGUID byte order and validates native counts, pointers, identifiers, and temporary allocation cleanup.
- Backfills public keys for Darks FIDO2 virtual credentials. Older Windows Hello or external credentials must be re-registered before cryptographic health verification.

Validation: the Release solution builds with zero compiler warnings/errors; the expanded security regression harness passes 20/20 on TPM 2.0; locked NuGet dependencies report no known vulnerable packages.

Distribution note: the attached development build is signed by the self-signed `CN=Darks FIDO2 Development` certificate and is published as a pre-release. It does not have public CA trust or SmartScreen reputation. Setup does not install certificates into a trusted store.

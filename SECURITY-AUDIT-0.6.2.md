# Protocol security review — 0.6.2

This focused maintainer review covers `CtapCbor.cs` and `WebAuthnService.cs`. It is not a third-party independent audit.

## Confirmed findings fixed

- **User verification was preferred, not required:** both Windows ceremonies used value `2`. They now use `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED` (`1`) and reject authenticator data without both UP and UV.
- **Health checks did not verify assertion signatures:** registration now stores the canonical ES256 COSE public key. Health checks verify the signature over `authenticatorData || SHA256(clientDataJSON)`.
- **Returned WebAuthn context was trusted without binding checks:** registration and assertion now verify the fixed RP-ID hash, credential ID, flags, credential type, signature presence, native lengths/pointers, and unsolicited data.
- **Signature counters were accepted without clone/malfunction detection:** a non-zero counter must increase relative to the encrypted vault record.
- **AAGUID byte order was interpreted as a native GUID:** AAGUID is now formatted using network byte order.
- **CTAP CBOR accepted non-canonical encodings:** the decoder rejects non-minimal integers/lengths, unsorted keys, indefinite lengths, unsupported composite keys, invalid UTF-8, and duplicate byte-string keys.
- **CTAP object allocation was bounded only per collection:** encoding and decoding now enforce document, collection, depth, and total-value ceilings.
- **CBOR map encoding depended on dictionary insertion order:** map keys are sorted using CTAP2 canonical major-type, encoded-length, and bytewise ordering.
- **Temporary native requests were freed without clearing:** tracked unmanaged strings, buffers, and structures are cleared before release.

## Regression coverage

The suite covers canonical ordering, non-minimal encodings, duplicate structural keys, composite keys, excessive nesting/collections/object counts, deterministic malformed-input fuzzing, RP mismatch, missing UV, credential mismatch, signature tampering, and counter rollback. The full hardware/security suite passes 20/20 on an Infineon TPM 2.0.

## Residual risk

- The Windows WebAuthn API and authenticator firmware remain trusted dependencies.
- Registration requests `none` attestation, so the application validates possession and protocol binding rather than asserting manufacturer provenance.
- Existing Windows Hello or external credentials lack the newly stored public key and must be re-registered for cryptographic health verification.
- A third-party source audit and production trusted code-signing certificate are still required before calling the project production-ready.

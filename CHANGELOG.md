# Changelog

All notable changes to `@attestto/cr-vc-sdk` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-11

Security release. The verifier substituted `#key-1` when a proof's `verificationMethod` carried no key fragment, so a proof that named no key at all was checked against a key the **verifier** picked. If the subject's DID Document happened to contain a `#key-1`, an unbound proof verified against it. On the signing side, `VCIssuer` defaulted `keyId` to `#key-1` for a DID of any method, producing credentials that named a verification method the issuer's own document does not contain. Both now refuse instead of guessing.

### Security
- **The verifier no longer chooses the key (SOC-174).** `verifyProof` previously read `hashIndex > 0 ? verificationMethod.substring(hashIndex) : '#key-1'`. A `verificationMethod` with no fragment now fails a `proof.verificationMethod` check and is rejected **before key resolution is attempted**, so the resolver is never asked for a key the proof did not name. Which key signed a credential is the proof's statement to make, not the verifier's to fill in.

### Changed
- **BREAKING (signer): `IssuerConfig.keyId` is now required** and must be a fragment starting with `#`. It previously defaulted to `#key-1`. `new VCIssuer({ did, privateKey })` now throws; pass the fragment the key actually has, for example `new VCIssuer({ did, privateKey, keyId: '#solana-key' })`.
  - `#key-1` is one DID method's convention, not a universal fragment. `did:sns` names its owner key `#solana-key` (method specification section 8.5), `did:key` and `did:jwk` use `#0`, and a `did:web` document names whatever it names. There is no method for which the old default was correct.
- `VCIssuer` exposes a read-only `keyId` getter so a caller can confirm what it configured.

### Notes
- This package carries a **standalone** verifier and does not depend on `@attestto/vc-sdk`, so the identical fix shipped in `@attestto/vc-sdk@0.4.0` does not reach here. It is applied twice on purpose. SOC-16 and SOC-19 were previously closed on the assumption that the dependency edge existed, and both stayed live for weeks.
- One downstream consumer, `attestto-desktop`, pins `@attestto/cr-vc-sdk@0.2.0`, which does not resolve to `0.4.0`. Nothing breaks on upgrade alone; it must pass `keyId` when it upgrades.
- This release removes the guess and requires the caller, which holds the key, to state its id. It does not make the SDK read the fragment out of a resolved DID Document; that remains the consumer's job.
- 100 tests pass (51 unit, the rest integration). The verifier case asserts that resolution is never **attempted** for a fragment-less proof, because asserting only `valid: false` would pass with the defect present: the fixture signature is invalid either way.

## [0.3.0] - 2026-08-06

### Security

**Two high-severity verification defects. Upgrade if you verify credentials.**

- **Verification is now fail-closed** (SOC-19). An unsigned credential, or one whose signature
  could not be verified because no `resolvePublicKey` resolver was configured, previously produced
  only a *warning* — `valid` stayed `true`. Callers writing `if (result.valid)` accepted unsigned
  credentials. Both cases are now errors.
- **Signatures are now bound to the credential issuer** (SOC-16). The verifying key was resolved
  from `proof.verificationMethod` — a field inside the object being verified, and therefore
  attacker-controlled — with no check that it belonged to `credential.issuer`. An attacker could
  sign with their own key, point `verificationMethod` at their own DID, claim any `issuer` they
  liked, and verify as valid. The signing key's DID must now equal the issuer.

### Added

- `VerificationResult.signatureVerified` — reports whether a cryptographically valid, issuer-bound
  proof was checked, independently of `valid`.
- `VerifyOptions.requireSignature` (default `true`) — set `false` for structural-only validation.
  `signatureVerified` still reports the real state.
- `VerifierConfig.verifyIssuerBinding` — optional hook for delegated signing, where the signing key
  belongs to a DID the issuer authorizes rather than the issuer itself. Resolve the issuer's DID
  document and return `true` only if the key is an authorized `assertionMethod`. A hook that
  throws is treated as "not authorized".
- `tests/verifier-parity.spec.ts` — keeps this verifier's security decisions aligned with
  `@attestto/vc-sdk`. The two are separate implementations and a fix to one does not reach the
  other; this file fails if they diverge.

### BREAKING

`verify()` now returns `valid: false` for credentials it previously accepted with a warning. This
is the point of the release. If you relied on the old behaviour for unsigned credentials, pass
`{ requireSignature: false }` explicitly and check `signatureVerified` yourself.

## [0.2.0] - 2026-04-17

### Added
- **10 new credential types** across 4 domains (22 total):
  - Citizen identity: CedulaIdentidadCR, DrivingLicenseCR, PassportCR, BasicDigitalLiteracyCredential
  - Signing: DocumentSignatureVC, AttesttoPdfSignature
  - Competency: DrivingTheoryExamCR, DrivingCompetencyCR
  - Medical: DictamenMedicoVC
  - Agreement: ConversationAgreementCredential
- Context routing for new domains: `attestto-signing-v1`, updated `cr-identity-v1` and `cr-driving-v1`.

### Fixed
- Exports field ordering: `types` condition now comes before `import`/`require` for correct TypeScript resolution in `moduleResolution: "bundler"` and `"node16"`.

## [0.1.0] - 2026-04-12

### Added
- Initial release: SDK for issuing and verifying Verifiable Credentials in the Costa Rica SSI ecosystem.
- **VCIssuer:** Issue signed VCs for 12 credential types with Ed25519 or ES256 algorithms. Linked Data proofs and JWT format. Pluggable issuer metadata (name, carneNumber, colegioId, jurisdiction).
- **VCVerifier:** Structural validation (9 checks), context routing, expiration/issuance date checks, cryptographic signature verification. Public key resolver interface for DID-based key lookup.
- **Key management:** `generateKeyPair()`, `sign()`, `verify()`, `toBase64url()`, `fromBase64url()`, `toHex()` for Ed25519 and ES256 (P-256).
- **12 credential types:** DrivingLicense, TheoreticalTestResult, PracticalTestResult, MedicalFitnessCredential, VehicleRegistration, VehicleTechnicalReview, CirculationRights, SOATCredential, DriverIdentity, TrafficViolation, AccidentReport, IdentityVC.
- **Context routing:** Driving types → `schemas.attestto.org/cr/driving/v1`, IdentityVC → `schemas.attestto.org/cr/identity/v1`.
- **IdentityVC:** Flat credentialSubject spread (natural person claims, organization roles/UBO, notarial attestation).
- StatusList2021 credential status support (placeholder — verification not yet implemented).
- Test suite: 83 tests — 34 unit (keys, issuer, verifier) + 49 integration (live schema URL validation, end-to-end issue→verify for all 12 types, ES256 cross-algorithm, schema-credential property alignment).
- `test:unit` and `test:integration` scripts for independent execution.
- Dual ESM/CJS build via tsup.

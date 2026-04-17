# Changelog

All notable changes to `@attestto/cr-vc-sdk` will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

/**
 * Parity tests — this repo's verifier vs `@attestto/vc-sdk`.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `cr-vc-sdk` carries its own `VCVerifier`. It is NOT a copy to be deleted: it
 * layers Costa Rica specifics (the `cr/driving/v1` and `cr/identity/v1` JSON-LD
 * contexts, CR credential types) on top of generic W3C VC verification. But the
 * *generic* half — is the proof present, is the signature valid, is the signing
 * key the issuer's — is duplicated logic, and duplicated verification logic is
 * exactly what let a vulnerability survive a fix.
 *
 * Two prior incidents make this concrete:
 *
 *   INC-2026-04-07-01 / INC-2026-08-06-03 (CORTEX) — a certificate-trust fix was
 *   applied to one of two implementations. The correct and the vulnerable code
 *   coexisted for four months while every artefact said the issue was closed.
 *
 *   SOC-16 / SOC-19 (this repo) — closed on 2026-07-19 with the remediation
 *   "bump @attestto/vc-sdk to ^0.3.0 and inherit the fix". There is no such
 *   dependency. Both defects were still live on 2026-08-06.
 *
 * These tests are the control that makes the duplication survivable: on the
 * security-relevant decisions, both verifiers must agree. If someone hardens one
 * and not the other, this file fails. That is its whole job.
 *
 * SCOPE: security decisions only — signed/unsigned, issuer-bound/not. CR context
 * and type checks are deliberately out of scope; divergence there is the point of
 * this package.
 */

import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair } from '../src/index.js'
import type { PublicKeyResolver } from '../src/verifier.js'

const ISSUER_DID = 'did:web:cosevi.attestto.id'
const ATTACKER_DID = 'did:web:attacker.example'

const issuerKeys = generateKeyPair('Ed25519')
const attackerKeys = generateKeyPair('Ed25519')

const issuer = new VCIssuer({ did: ISSUER_DID, privateKey: issuerKeys.privateKey })

/** Resolves both the honest issuer and the attacker — a permissive resolver is
 *  the realistic case, and is precisely the condition SOC-16 is about. */
const resolver: PublicKeyResolver = async (did: string) => {
  if (did === ISSUER_DID) return { publicKey: issuerKeys.publicKey, algorithm: 'Ed25519' }
  if (did === ATTACKER_DID) return { publicKey: attackerKeys.publicKey, algorithm: 'Ed25519' }
  return null
}

async function legitimateCredential() {
  return issuer.issue({
    type: 'DrivingLicense',
    subjectDid: 'did:web:maria.attestto.id',
    claims: { licenseNumber: 'CR-2026-000001', categories: ['B'], status: 'active' },
  })
}

describe('parity: the security verdict must not depend on which verifier you reach for', () => {
  it('a genuinely signed, issuer-bound credential verifies', async () => {
    const vc = await legitimateCredential()
    const result = await new VCVerifier({ resolvePublicKey: resolver }).verify(vc)

    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })

  it('an unsigned credential is rejected — never a warning-only pass', async () => {
    const vc = await legitimateCredential()
    const { proof: _proof, ...unsigned } = vc

    const result = await new VCVerifier({ resolvePublicKey: resolver }).verify(
      unsigned as typeof vc
    )

    // The exact defect of SOC-19: `valid` must not be true just because the
    // structural checks passed and the missing proof was only a warning.
    expect(result.valid).toBe(false)
    expect(result.signatureVerified).toBe(false)
  })

  it('a credential with no resolver configured is rejected, not silently unverified', async () => {
    const vc = await legitimateCredential()
    const result = await new VCVerifier().verify(vc)

    expect(result.valid).toBe(false)
    expect(result.signatureVerified).toBe(false)
  })

  it('signatureVerified stays honest even when requireSignature is opted out', async () => {
    const vc = await legitimateCredential()
    const { proof: _proof, ...unsigned } = vc

    const result = await new VCVerifier({ resolvePublicKey: resolver }).verify(
      unsigned as typeof vc,
      { requireSignature: false }
    )

    // Structural-only validation is a legitimate caller choice. Lying about
    // whether a signature was checked is not.
    expect(result.signatureVerified).toBe(false)
  })
})

describe('parity: no verifier in this estate may accept an issuer it did not verify', () => {
  it('rejects a valid signature made by a key that is not the claimed issuer', async () => {
    // The forgery SOC-16 describes: the attacker signs with their own key and
    // points verificationMethod at their own DID, while `issuer` names COSEVI.
    // Every cryptographic check passes. Only the binding check catches it.
    const forged = await new VCIssuer({
      did: ATTACKER_DID,
      privateKey: attackerKeys.privateKey,
    }).issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-2026-000001', categories: ['B'], status: 'active' },
    })
    const impersonating = { ...forged, issuer: ISSUER_DID }

    const result = await new VCVerifier({ resolvePublicKey: resolver }).verify(impersonating)

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.toLowerCase().includes('not bound'))).toBe(true)
  })

  it('the issuer-binding check is a real gate, not a field that is always true', async () => {
    // "Rejects everything" and "rejects forgeries" look identical from outside.
    // A legitimate credential must still pass the same check the forgery fails.
    const legit = await legitimateCredential()
    const result = await new VCVerifier({ resolvePublicKey: resolver }).verify(legit)

    const binding = result.checks.find((c) => c.check === 'proof.issuerBinding')
    expect(binding).toBeDefined()
    expect(binding?.passed).toBe(true)
  })

  it('a throwing issuer-binding hook fails closed', async () => {
    const vc = await legitimateCredential()
    const result = await new VCVerifier({
      resolvePublicKey: resolver,
      verifyIssuerBinding: async () => {
        throw new Error('DID document unreachable')
      },
    }).verify(vc)

    // An unreachable DID document means "not proven authorized", never "assume so".
    expect(result.valid).toBe(false)
  })
})

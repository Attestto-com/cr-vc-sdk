/**
 * Security regression tests for VCVerifier.
 *
 * SOC-16: signatures must be bound to the credential issuer.
 * SOC-19: verification is fail-closed — unsigned / unverifiable credentials
 *         are NOT valid.
 */

import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair, sign, toBase64url } from '../src/index.js'
import type { PublicKeyResolver } from '../src/verifier.js'

const issuerKeys = generateKeyPair('Ed25519')
const issuer = new VCIssuer({ did: 'did:web:cosevi.attestto.id', keyId: '#key-0',
  privateKey: issuerKeys.privateKey })

function resolverFor(did: string, publicKey: Uint8Array): PublicKeyResolver {
  return async (d: string) => (d === did ? { publicKey, algorithm: 'Ed25519' } : null)
}

async function issueLegit() {
  return issuer.issue({
    type: 'DrivingLicense',
    subjectDid: 'did:web:maria.attestto.id',
    claims: { licenseNumber: 'CR-2026-000001', categories: ['B'], status: 'active' },
  })
}

describe('SOC-19: fail-closed verification', () => {
  it('a legitimately signed, issuer-bound credential is valid and signatureVerified', async () => {
    const vc = await issueLegit()
    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:cosevi.attestto.id', issuerKeys.publicKey) })
    const result = await verifier.verify(vc)
    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })

  it('an unsigned credential is NOT valid by default', async () => {
    const vc = await issueLegit()
    const { proof: _p, ...unsigned } = vc
    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:cosevi.attestto.id', issuerKeys.publicKey) })
    const result = await verifier.verify(unsigned as typeof vc)
    expect(result.valid).toBe(false)
    expect(result.signatureVerified).toBe(false)
    expect(result.errors.some((e) => e.includes('unsigned'))).toBe(true)
  })
})

describe('SOC-16: signature must be bound to the issuer', () => {
  it('rejects a forged credential: valid signature by an attacker key claiming a trusted issuer', async () => {
    // Attacker controls did:web:attacker with a resolvable key. They craft a
    // credential that CLAIMS issuer = COSEVI, sign it with their own key, and
    // point verificationMethod at their own DID.
    const attacker = generateKeyPair('Ed25519')
    const base = await issueLegit()
    const { proof: _p, ...unsigned } = base
    const forgedUnsigned = { ...unsigned, issuer: 'did:web:cosevi.attestto.id' }

    const message = new TextEncoder().encode(JSON.stringify(forgedUnsigned))
    const signature = sign(message, attacker.privateKey, 'Ed25519')
    const forged = {
      ...forgedUnsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:attacker.example#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(signature),
      },
    } as typeof base

    const verifier = new VCVerifier({ resolvePublicKey: resolverFor('did:web:attacker.example', attacker.publicKey) })
    const result = await verifier.verify(forged)

    expect(result.signatureVerified).toBe(false)
    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('not bound to the credential issuer'))).toBe(true)
  })

  it('accepts a delegated key when verifyIssuerBinding authorizes it', async () => {
    const delegate = generateKeyPair('Ed25519')
    const base = await issueLegit()
    const { proof: _p, ...unsigned } = base
    const message = new TextEncoder().encode(JSON.stringify(unsigned))
    const signature = sign(message, delegate.privateKey, 'Ed25519')
    const delegated = {
      ...unsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: 'did:web:signer.attestto.id#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(signature),
      },
    } as typeof base

    const verifier = new VCVerifier({
      resolvePublicKey: resolverFor('did:web:signer.attestto.id', delegate.publicKey),
      verifyIssuerBinding: async (iss, vm) =>
        iss === 'did:web:cosevi.attestto.id' && vm === 'did:web:signer.attestto.id#key-1',
    })
    const result = await verifier.verify(delegated)
    expect(result.valid).toBe(true)
    expect(result.signatureVerified).toBe(true)
  })
})

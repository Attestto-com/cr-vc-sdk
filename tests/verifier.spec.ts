import { describe, it, expect } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair } from '../src/index.js'

describe('VCVerifier', () => {
  const keys = generateKeyPair('Ed25519')
  const testIssuer = new VCIssuer({
    did: 'did:web:cosevi.attestto.id',
    privateKey: keys.privateKey,
  })

  it('verifies a valid credential with known public key', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      expirationDate: '2032-04-01T23:59:59Z',
      claims: {
        licenseNumber: 'CR-2026-045678',
        categories: ['B'],
        status: 'active',
        points: 12,
      },
    })

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
      expectedType: 'DrivingLicense',
      expectedIssuer: 'did:web:cosevi.attestto.id',
    })

    expect(result.valid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  it('detects tampered credential', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
        licenseNumber: 'CR-2026-045678',
        categories: ['B'],
        status: 'active',
      },
    })

    // Tamper with the credential
    const license = vc.credentialSubject.license as Record<string, unknown>
    license.status = 'suspended'

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519')

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('Invalid signature')
  })

  it('detects wrong issuer', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
      expectedIssuer: 'did:web:fake-issuer.example.com',
    })

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('Expected issuer'))).toBe(true)
  })

  it('detects wrong credential type', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
      expectedType: 'MedicalFitnessCredential',
    })

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('Expected credential type'))).toBe(true)
  })

  it('detects expired credential', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      expirationDate: '2020-01-01T00:00:00Z',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519')

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('expired'))).toBe(true)
  })

  it('warns about missing proof when no resolver configured', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    const verifier = new VCVerifier() // No resolver
    const result = await verifier.verify(vc)

    // Valid because structure is correct, but warning about unverified signature
    expect(result.warnings.some((w) => w.includes('not verified'))).toBe(true)
  })

  it('verifies with public key resolver', async () => {
    const vc = await testIssuer.issue({
      type: 'TheoreticalTestResult',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
        status: 'approved',
        score: 88,
        passingScore: 70,
        category: 'B',
        modality: 'online',
        testCenterDID: 'did:web:academia.attestto.id',
        examVersionHash: 'sha256:abc',
      },
    })

    const verifier = new VCVerifier({
      resolvePublicKey: async (did) => {
        if (did === 'did:web:cosevi.attestto.id') {
          return { publicKey: keys.publicKey, algorithm: 'Ed25519' }
        }
        return null
      },
    })

    const result = await verifier.verify(vc, {
      expectedType: 'TheoreticalTestResult',
    })

    expect(result.valid).toBe(true)
  })

  it('fails when public key cannot be resolved', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    const verifier = new VCVerifier({
      resolvePublicKey: async () => null,
    })

    const result = await verifier.verify(vc)

    expect(result.valid).toBe(false)
    expect(result.errors.some((e) => e.includes('Could not resolve'))).toBe(true)
  })

  it('detects wrong signing key', async () => {
    const vc = await testIssuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    // Verify with a different key pair
    const wrongKeys = generateKeyPair('Ed25519')
    const verifier = new VCVerifier()
    const result = await verifier.verifyWithKey(vc, wrongKeys.publicKey, 'Ed25519')

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('Invalid signature')
  })

  it('validates structure of malformed credential', async () => {
    const malformed = {
      '@context': [],
      type: ['NotAVC'],
      issuer: 'not-a-did',
      credentialSubject: {},
    } as any

    const verifier = new VCVerifier()
    const result = await verifier.verify(malformed)

    expect(result.valid).toBe(false)
    expect(result.errors.length).toBeGreaterThanOrEqual(3)
  })
})

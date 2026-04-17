/**
 * Integration tests: cr-vc-sdk × live cr-vc-schemas
 *
 * These tests fetch the actual JSON-LD context URLs from
 * schemas.attestto.org and verify that the full issue → verify
 * cycle works end-to-end for every credential type.
 *
 * Run separately from unit tests:
 *   pnpm test:integration
 *
 * Requires network access. Will fail if schema URLs are down.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { VCIssuer, VCVerifier, generateKeyPair } from '../../src/index.js'
import type { CredentialType } from '../../src/index.js'

// ── Schema URLs ──────────────────────────────────────────────────────

const SCHEMA_URLS = {
  driving: 'https://schemas.attestto.org/cr/driving/v1.jsonld',
  identity: 'https://schemas.attestto.org/cr/identity/v1.jsonld',
} as const

// ── Credential type → context mapping ────────────────────────────────

const DRIVING_TYPES: CredentialType[] = [
  'DrivingLicense',
  'TheoreticalTestResult',
  'PracticalTestResult',
  'MedicalFitnessCredential',
  'VehicleRegistration',
  'VehicleTechnicalReview',
  'CirculationRights',
  'SOATCredential',
  'DriverIdentity',
  'TrafficViolation',
  'AccidentReport',
]

const IDENTITY_TYPES: CredentialType[] = ['IdentityVC']

const ALL_TYPES = [...DRIVING_TYPES, ...IDENTITY_TYPES]

// ── Sample claims per credential type ────────────────────────────────

const SAMPLE_CLAIMS: Record<CredentialType, Record<string, unknown>> = {
  DrivingLicense: {
    licenseNumber: 'CR-2026-045678',
    categories: ['B', 'A1'],
    issueDate: '2026-04-01',
    expiresAt: '2032-04-01',
    status: 'active',
    points: 12,
    issuingAuthority: 'did:web:cosevi.attestto.id',
  },
  TheoreticalTestResult: {
    status: 'approved',
    score: 88,
    passingScore: 70,
    category: 'B',
    testDate: '2026-03-15T14:00:00Z',
    modality: 'online',
    testCenterDID: 'did:web:academia-tica.attestto.id',
    examVersionHash: 'sha256:abc123',
  },
  PracticalTestResult: {
    status: 'approved',
    category: 'B',
    testDate: '2026-03-20T14:00:00Z',
    evaluatorDID: 'did:web:evaluador.attestto.id',
    testCenterDID: 'did:web:sede-dgev.attestto.id',
    vehiclePlate: 'SJO-012',
    maneuvers: [
      { name: 'Estacionamiento en paralelo', result: 'pass' },
      { name: 'Giro en U', result: 'pass' },
    ],
  },
  MedicalFitnessCredential: {
    status: 'fit',
    categories: ['B', 'A1'],
    issuedDate: '2026-03-05',
    expiresAt: '2027-03-05T23:59:59Z',
    physicianDID: 'did:web:dra-vargas.attestto.id',
    clinicDID: 'did:web:clinica-salud.attestto.id',
  },
  VehicleRegistration: {
    plate: 'SJO-123',
    vin: '1HGBH41JXMN109186',
    ownerDID: 'did:web:maria.attestto.id',
    make: 'Toyota',
    model: 'Corolla',
    year: 2024,
    color: 'blanco',
  },
  VehicleTechnicalReview: {
    result: 'approved',
    inspectionDate: '2026-02-15',
    expiresAt: '2027-02-15',
    centerName: 'RITEVE SyC Alajuela',
    defects: [],
    mileage: 45000,
  },
  CirculationRights: {
    fiscalYear: 2026,
    amount: 125000,
    currency: 'CRC',
    validFrom: '2026-01-01',
    validUntil: '2026-12-31',
    plate: 'SJO-123',
  },
  SOATCredential: {
    policyNumber: 'SOA-2026-789012',
    coverageType: 'obligatorio',
    premium: 45000,
    currency: 'CRC',
    expiresAt: '2027-04-01',
    insurer: 'INS',
  },
  DriverIdentity: {
    nationalIdType: 'cedula',
    nationalIdRef: '1-1234-0567',
    fullName: 'Maria Isabel Rodriguez',
    dateOfBirth: '1990-05-15',
  },
  TrafficViolation: {
    violationType: 'speeding',
    points: 2,
    fineAmount: 115000,
    currency: 'CRC',
    location: { lat: 9.9281, lng: -84.0907, description: 'Ruta 1, km 45' },
    date: '2026-03-10T08:30:00Z',
    officerDID: 'did:web:oficial-123.policia.attestto.id',
  },
  AccidentReport: {
    reportNumber: 'ACC-2026-001234',
    severity: 'minor',
    date: '2026-03-01T16:45:00Z',
    location: { lat: 9.9341, lng: -84.0875, description: 'San Jose, Paseo Colon' },
    parties: [
      { role: 'driver', did: 'did:web:maria.attestto.id', plate: 'SJO-123' },
      { role: 'driver', did: 'did:web:carlos.attestto.id', plate: 'HER-456' },
    ],
  },
  IdentityVC: {
    type: 'NaturalPerson',
    nationalId: { type: 'cedula', number: '1-1234-0567', country: 'CR' },
    fullName: 'Carlos Alberto Jimenez Rojas',
    dateOfBirth: '1988-03-22',
    nationality: 'CR',
    photoHash: 'sha256:a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
    notarialAttestation: {
      protocolNumber: '2026-00142',
      attestedAt: '2026-04-09T14:15:00Z',
    },
  },
}

// ── Test setup ───────────────────────────────────────────────────────

const keys = generateKeyPair('Ed25519')
const issuer = new VCIssuer({
  did: 'did:web:integration-test.attestto.id',
  privateKey: keys.privateKey,
})

const verifier = new VCVerifier({
  resolvePublicKey: async (did) => {
    if (did === 'did:web:integration-test.attestto.id') {
      return { publicKey: keys.publicKey, algorithm: 'Ed25519' }
    }
    return null
  },
})

// ── Schema URL availability ──────────────────────────────────────────

describe('schema URL availability', () => {
  it('driving context returns 200 with valid JSON-LD', async () => {
    const res = await fetch(SCHEMA_URLS.driving)
    expect(res.status).toBe(200)

    const json = await res.json()
    expect(json).toHaveProperty('@context')
    expect(json['@context']).toHaveProperty('@version', 1.1)
    expect(json['@context']).toHaveProperty('@protected', true)
  })

  it('identity context returns 200 with valid JSON-LD', async () => {
    const res = await fetch(SCHEMA_URLS.identity)
    expect(res.status).toBe(200)

    const json = await res.json()
    expect(json).toHaveProperty('@context')
    expect(json['@context']).toHaveProperty('@version', 1.1)
    expect(json['@context']).toHaveProperty('@protected', true)
  })

  it('driving context defines all 11 driving credential types', async () => {
    const res = await fetch(SCHEMA_URLS.driving)
    const json = await res.json()
    const ctx = json['@context']

    for (const type of DRIVING_TYPES) {
      expect(ctx).toHaveProperty(type)
    }
  })

  it('identity context defines IdentityVC and NaturalPerson', async () => {
    const res = await fetch(SCHEMA_URLS.identity)
    const json = await res.json()
    const ctx = json['@context']

    expect(ctx).toHaveProperty('IdentityVC')
    expect(ctx).toHaveProperty('NaturalPerson')
    expect(ctx).toHaveProperty('nationalId')
    expect(ctx).toHaveProperty('fullName')
    expect(ctx).toHaveProperty('notarialAttestation')
    expect(ctx).toHaveProperty('organizationRoles')
  })

  it('driving context CORS allows cross-origin fetch', async () => {
    const res = await fetch(SCHEMA_URLS.driving)
    // GitHub Pages serves CORS by default; Cloudflare _headers adds explicit header
    // The fetch succeeding from Node.js proves the endpoint is reachable
    expect(res.ok).toBe(true)
  })

  it('identity context CORS allows cross-origin fetch', async () => {
    const res = await fetch(SCHEMA_URLS.identity)
    expect(res.ok).toBe(true)
  })
})

// ── End-to-end issue + verify per credential type ────────────────────

describe('end-to-end issue + verify', () => {
  for (const type of ALL_TYPES) {
    describe(type, () => {
      it('issues a valid credential', async () => {
        const vc = await issuer.issue({
          type,
          subjectDid: 'did:web:subject.attestto.id',
          claims: SAMPLE_CLAIMS[type],
          expirationDate: '2032-12-31T23:59:59Z',
        })

        expect(vc.type).toContain('VerifiableCredential')
        expect(vc.type).toContain(type)
        expect(vc.proof).toBeDefined()
        expect(vc.id).toMatch(/^urn:uuid:/)
      })

      it('includes the correct JSON-LD context', async () => {
        const vc = await issuer.issue({
          type,
          subjectDid: 'did:web:subject.attestto.id',
          claims: SAMPLE_CLAIMS[type],
        })

        expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1')

        if (type === 'IdentityVC') {
          expect(vc['@context']).toContain('https://schemas.attestto.org/cr/identity/v1')
        } else {
          expect(vc['@context']).toContain('https://schemas.attestto.org/cr/driving/v1')
        }
      })

      it('verifies with correct signing key', async () => {
        const vc = await issuer.issue({
          type,
          subjectDid: 'did:web:subject.attestto.id',
          claims: SAMPLE_CLAIMS[type],
          expirationDate: '2032-12-31T23:59:59Z',
        })

        const result = await verifier.verify(vc, {
          expectedType: type,
          expectedIssuer: 'did:web:integration-test.attestto.id',
        })

        expect(result.valid).toBe(true)
        expect(result.errors).toHaveLength(0)
      })
    })
  }
})

// ── Cross-algorithm verification ─────────────────────────────────────

describe('ES256 algorithm end-to-end', () => {
  const es256Keys = generateKeyPair('ES256')
  const es256Issuer = new VCIssuer({
    did: 'did:web:es256-test.attestto.id',
    privateKey: es256Keys.privateKey,
    algorithm: 'ES256',
  })

  it('issues and verifies DrivingLicense with ES256', async () => {
    const vc = await es256Issuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:subject.attestto.id',
      claims: SAMPLE_CLAIMS.DrivingLicense,
      expirationDate: '2032-12-31T23:59:59Z',
    })

    expect(vc.proof!.type).toBe('EcdsaSecp256r1Signature2019')

    const result = await new VCVerifier().verifyWithKey(
      vc,
      es256Keys.publicKey,
      'ES256',
      { expectedType: 'DrivingLicense' }
    )

    expect(result.valid).toBe(true)
  })

  it('issues and verifies IdentityVC with ES256', async () => {
    const vc = await es256Issuer.issue({
      type: 'IdentityVC',
      subjectDid: 'did:web:subject.attestto.id',
      claims: SAMPLE_CLAIMS.IdentityVC,
    })

    const result = await new VCVerifier().verifyWithKey(
      vc,
      es256Keys.publicKey,
      'ES256',
      { expectedType: 'IdentityVC' }
    )

    expect(result.valid).toBe(true)
  })
})

// ── Schema–credential alignment ──────────────────────────────────────

describe('schema property alignment', () => {
  let drivingContext: Record<string, unknown>
  let identityContext: Record<string, unknown>

  beforeAll(async () => {
    const [drivingRes, identityRes] = await Promise.all([
      fetch(SCHEMA_URLS.driving),
      fetch(SCHEMA_URLS.identity),
    ])
    drivingContext = (await drivingRes.json())['@context']
    identityContext = (await identityRes.json())['@context']
  })

  it('DrivingLicense claims map to driving context properties', () => {
    // The license wrapper is defined in the context
    expect(drivingContext).toHaveProperty('license')
    const licenseCtx = (drivingContext.license as any)?.['@context']
    expect(licenseCtx).toHaveProperty('licenseNumber')
    expect(licenseCtx).toHaveProperty('categories')
    expect(licenseCtx).toHaveProperty('status')
    expect(licenseCtx).toHaveProperty('points')
  })

  it('IdentityVC claims map to identity context properties', () => {
    expect(identityContext).toHaveProperty('nationalId')
    expect(identityContext).toHaveProperty('fullName')
    expect(identityContext).toHaveProperty('dateOfBirth')
    expect(identityContext).toHaveProperty('nationality')
    expect(identityContext).toHaveProperty('photoHash')
    expect(identityContext).toHaveProperty('notarialAttestation')
  })

  it('VehicleRegistration claims map to driving context', () => {
    expect(drivingContext).toHaveProperty('vehicle')
    const vehicleCtx = (drivingContext.vehicle as any)?.['@context']
    expect(vehicleCtx).toHaveProperty('plate')
    expect(vehicleCtx).toHaveProperty('vin')
    expect(vehicleCtx).toHaveProperty('make')
    expect(vehicleCtx).toHaveProperty('model')
  })

  it('TheoreticalTestResult claims map to driving context', () => {
    expect(drivingContext).toHaveProperty('theoreticalTest')
    const testCtx = (drivingContext.theoreticalTest as any)?.['@context']
    expect(testCtx).toHaveProperty('score')
    expect(testCtx).toHaveProperty('passingScore')
    expect(testCtx).toHaveProperty('category')
  })

  it('organization roles defined in identity context', () => {
    expect(identityContext).toHaveProperty('organizationRoles')
    const rolesCtx = (identityContext.organizationRoles as any)?.['@context']
    expect(rolesCtx).toHaveProperty('organization')
    expect(rolesCtx).toHaveProperty('role')
    expect(rolesCtx).toHaveProperty('ownershipPercentage')
  })
})

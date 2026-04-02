import { describe, it, expect } from 'vitest'
import { VCIssuer, generateKeyPair } from '../src/index.js'

describe('VCIssuer', () => {
  const keys = generateKeyPair('Ed25519')
  const issuer = new VCIssuer({
    did: 'did:web:cosevi.attestto.id',
    privateKey: keys.privateKey,
  })

  it('issues a DrivingLicense credential', async () => {
    const vc = await issuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
        licenseNumber: 'CR-2026-045678',
        categories: ['B', 'A1'],
        issueDate: '2026-04-01',
        expiresAt: '2032-04-01',
        status: 'active',
        points: 12,
        issuingAuthority: 'did:web:cosevi.attestto.id',
      },
    })

    expect(vc.type).toContain('VerifiableCredential')
    expect(vc.type).toContain('DrivingLicense')
    expect(vc.issuer).toBe('did:web:cosevi.attestto.id')
    expect(vc.credentialSubject.id).toBe('did:web:maria.attestto.id')
    expect(vc.credentialSubject.license).toBeDefined()
    expect((vc.credentialSubject.license as any).licenseNumber).toBe('CR-2026-045678')
    expect(vc.proof).toBeDefined()
    expect(vc.proof!.type).toBe('Ed25519Signature2020')
    expect(vc.proof!.verificationMethod).toBe('did:web:cosevi.attestto.id#key-1')
    expect(vc['@context']).toContain('https://schemas.attestto.org/cr/driving/v1')
  })

  it('issues a TheoreticalTestResult credential', async () => {
    const dgev = new VCIssuer({
      did: 'did:web:dgev.attestto.id',
      privateKey: generateKeyPair().privateKey,
    })

    const vc = await dgev.issue({
      type: 'TheoreticalTestResult',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
        status: 'approved',
        score: 88,
        passingScore: 70,
        category: 'B',
        testDate: '2026-03-15T14:00:00Z',
        modality: 'online',
        testCenterDID: 'did:web:academia-tica.attestto.id',
        examVersionHash: 'sha256:abc123',
      },
    })

    expect(vc.type).toContain('TheoreticalTestResult')
    expect(vc.credentialSubject.theoreticalTest).toBeDefined()
    expect((vc.credentialSubject.theoreticalTest as any).score).toBe(88)
  })

  it('issues a PracticalTestResult credential', async () => {
    const vc = await issuer.issue({
      type: 'PracticalTestResult',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
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
    })

    expect(vc.type).toContain('PracticalTestResult')
    expect(vc.credentialSubject.practicalTest).toBeDefined()
    const test = vc.credentialSubject.practicalTest as any
    expect(test.maneuvers).toHaveLength(2)
    expect(test.vehiclePlate).toBe('SJO-012')
  })

  it('issues a MedicalFitnessCredential', async () => {
    const clinic = new VCIssuer({
      did: 'did:web:clinica-salud.attestto.id',
      privateKey: generateKeyPair().privateKey,
    })

    const vc = await clinic.issue({
      type: 'MedicalFitnessCredential',
      subjectDid: 'did:web:maria.attestto.id',
      claims: {
        status: 'fit',
        categories: ['B', 'A1'],
        issuedDate: '2026-03-05',
        expiresAt: '2027-03-05T23:59:59Z',
        physicianDID: 'did:web:dra-vargas.attestto.id',
        clinicDID: 'did:web:clinica-salud.attestto.id',
      },
    })

    expect(vc.type).toContain('MedicalFitnessCredential')
    expect(vc.credentialSubject.fitness).toBeDefined()
  })

  it('generates unique credential IDs', async () => {
    const vc1 = await issuer.issue({
      type: 'DriverIdentity',
      subjectDid: 'did:web:test.attestto.id',
      claims: { nationalIdType: 'cedula', nationalIdRef: '****-5678' },
    })
    const vc2 = await issuer.issue({
      type: 'DriverIdentity',
      subjectDid: 'did:web:test.attestto.id',
      claims: { nationalIdType: 'cedula', nationalIdRef: '****-5678' },
    })

    expect(vc1.id).not.toBe(vc2.id)
    expect(vc1.id).toMatch(/^urn:uuid:/)
  })

  it('includes expiration date when provided', async () => {
    const vc = await issuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:test.attestto.id',
      expirationDate: '2032-04-01T23:59:59Z',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
    })

    expect(vc.expirationDate).toBe('2032-04-01T23:59:59Z')
  })

  it('includes credential status when provided', async () => {
    const vc = await issuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:test.attestto.id',
      claims: { licenseNumber: 'CR-TEST', categories: ['B'], status: 'active' },
      credentialStatus: {
        id: 'https://status.attestto.org/cr/credentials/status/1#4567',
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: '4567',
        statusListCredential: 'https://status.attestto.org/cr/credentials/status-list/1',
      },
    })

    expect(vc.credentialStatus).toBeDefined()
    expect(vc.credentialStatus!.type).toBe('StatusList2021Entry')
  })

  it('throws on unknown credential type', async () => {
    await expect(
      issuer.issue({
        type: 'UnknownType' as any,
        subjectDid: 'did:web:test.attestto.id',
        claims: {},
      })
    ).rejects.toThrow('Unknown credential type')
  })

  it('issues all 11 credential types', async () => {
    const types = [
      'DrivingLicense', 'TheoreticalTestResult', 'PracticalTestResult',
      'MedicalFitnessCredential', 'VehicleRegistration', 'VehicleTechnicalReview',
      'CirculationRights', 'SOATCredential', 'DriverIdentity',
      'TrafficViolation', 'AccidentReport',
    ] as const

    for (const type of types) {
      const vc = await issuer.issue({
        type,
        subjectDid: 'did:web:test.attestto.id',
        claims: { testField: 'value' },
      })
      expect(vc.type).toContain(type)
    }
  })
})

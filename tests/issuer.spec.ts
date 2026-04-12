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

  it('issues all 12 credential types', async () => {
    const types = [
      'DrivingLicense', 'TheoreticalTestResult', 'PracticalTestResult',
      'MedicalFitnessCredential', 'VehicleRegistration', 'VehicleTechnicalReview',
      'CirculationRights', 'SOATCredential', 'DriverIdentity',
      'TrafficViolation', 'AccidentReport', 'IdentityVC',
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

  it('issues an IdentityVC with natural person claims (flat subject)', async () => {
    const notary = new VCIssuer({
      did: 'did:sns:notario-garcia.abogados.attestto.sol',
      privateKey: generateKeyPair().privateKey,
    })

    const vc = await notary.issue({
      type: 'IdentityVC',
      subjectDid: 'did:sns:carlos.attestto.sol',
      claims: {
        type: 'NaturalPerson',
        nationalId: { type: 'cedula', number: '1-1234-0567', country: 'CR' },
        fullName: 'Carlos Alberto Jimenez Rojas',
        dateOfBirth: '1988-03-22',
        nationality: 'CR',
        maritalStatus: 'casado',
        photoHash: 'sha256:a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
        notarialAttestation: {
          protocolNumber: '2026-00142',
          attestedAt: '2026-04-09T14:15:00Z',
        },
      },
      expirationDate: '2036-04-09T14:30:00Z',
    })

    expect(vc.type).toContain('VerifiableCredential')
    expect(vc.type).toContain('IdentityVC')
    expect(vc['@context']).toContain('https://schemas.attestto.org/cr/identity/v1')
    expect(vc['@context']).not.toContain('https://schemas.attestto.org/cr/driving/v1')
    expect(vc.credentialSubject.id).toBe('did:sns:carlos.attestto.sol')
    expect(vc.credentialSubject.type).toBe('NaturalPerson')
    expect(vc.credentialSubject.fullName).toBe('Carlos Alberto Jimenez Rojas')
    expect((vc.credentialSubject.nationalId as any).type).toBe('cedula')
    expect(vc.credentialSubject.notarialAttestation).toBeDefined()
    expect(vc.proof).toBeDefined()
  })

  it('issues an IdentityVC with organization roles (UBO)', async () => {
    const notary = new VCIssuer({
      did: 'did:sns:notario.attestto.sol',
      privateKey: generateKeyPair().privateKey,
    })

    const vc = await notary.issue({
      type: 'IdentityVC',
      subjectDid: 'did:sns:maria.attestto.sol',
      claims: {
        type: 'NaturalPerson',
        nationalId: { type: 'cedula', number: '2-0456-0789', country: 'CR' },
        fullName: 'Maria Isabel Rodriguez Solano',
        dateOfBirth: '1975-08-15',
        photoHash: 'sha256:0000000000000000000000000000000000000000000000000000000000000001',
        notarialAttestation: { protocolNumber: '2026-00200', attestedAt: '2026-04-11T10:00:00Z' },
        organizationRoles: [
          {
            organization: { legalName: 'Inversiones Rodriguez S.A.', taxId: '3-101-654321', jurisdiction: 'CR' },
            role: 'ubo',
            ownershipPercentage: 60,
            hasVotingControl: true,
            position: 'Presidente',
          },
          {
            organization: { legalName: 'Exportadora del Valle Ltda', taxId: '3-102-111222', jurisdiction: 'CR' },
            role: 'legal_representative',
            poderType: 'generalisimo',
          },
        ],
      },
    })

    expect(vc.credentialSubject.organizationRoles).toBeDefined()
    const roles = vc.credentialSubject.organizationRoles as any[]
    expect(roles).toHaveLength(2)
    expect(roles[0].role).toBe('ubo')
    expect(roles[0].ownershipPercentage).toBe(60)
    expect(roles[1].role).toBe('legal_representative')
    expect(roles[1].poderType).toBe('generalisimo')
  })

  it('issues an IdentityVC with rich issuer metadata', async () => {
    const notary = new VCIssuer({
      did: 'did:sns:notario-garcia.abogados.attestto.sol',
      privateKey: generateKeyPair().privateKey,
    })

    const vc = await notary.issue({
      type: 'IdentityVC',
      subjectDid: 'did:sns:citizen.attestto.sol',
      claims: {
        type: 'NaturalPerson',
        nationalId: { type: 'cedula', number: '1-0000-0000', country: 'CR' },
        fullName: 'Test Citizen',
        dateOfBirth: '1990-01-01',
        photoHash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        notarialAttestation: { protocolNumber: '2026-00001', attestedAt: '2026-04-11T00:00:00Z' },
      },
      issuerInfo: {
        name: 'Ana Garcia Morales',
        carneNumber: 'AB-12345',
        colegioId: 'did:sns:colegio-abogados.attestto.sol',
        jurisdiction: 'CR',
      },
    })

    expect(typeof vc.issuer).toBe('object')
    const issuerObj = vc.issuer as { id: string; name: string; carneNumber?: string }
    expect(issuerObj.id).toBe('did:sns:notario-garcia.abogados.attestto.sol')
    expect(issuerObj.name).toBe('Ana Garcia Morales')
    expect(issuerObj.carneNumber).toBe('AB-12345')
  })

  it('DrivingLicense still uses driving context (regression)', async () => {
    const vc = await issuer.issue({
      type: 'DrivingLicense',
      subjectDid: 'did:web:test.attestto.id',
      claims: { licenseNumber: 'CR-REG', categories: ['B'], status: 'active' },
    })

    expect(vc['@context']).toContain('https://schemas.attestto.org/cr/driving/v1')
    expect(vc['@context']).not.toContain('https://schemas.attestto.org/cr/identity/v1')
    expect(typeof vc.issuer).toBe('string')
  })
})

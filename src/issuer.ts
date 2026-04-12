/**
 * VCIssuer — Create and sign Verifiable Credentials
 *
 * Usage:
 * ```ts
 * import { VCIssuer, generateKeyPair } from '@attestto-com/cr-vc-sdk'
 *
 * const keys = generateKeyPair()
 * const issuer = new VCIssuer({
 *   did: 'did:web:cosevi.attestto.id',
 *   privateKey: keys.privateKey,
 * })
 *
 * const vc = await issuer.issue({
 *   type: 'DrivingLicense',
 *   subjectDid: 'did:web:maria.attestto.id',
 *   claims: {
 *     license: {
 *       licenseNumber: 'CR-2026-045678',
 *       categories: ['B'],
 *       issueDate: '2026-04-01',
 *       expiresAt: '2032-04-01',
 *       status: 'active',
 *       points: 12,
 *       issuingAuthority: 'did:web:cosevi.attestto.id',
 *     }
 *   }
 * })
 * ```
 */

import { SignJWT } from 'jose'
import { sign, toBase64url } from './keys.js'
import type { IssuerConfig, IssueOptions, VerifiableCredential, Proof } from './types.js'

const CR_DRIVING_CONTEXT = 'https://schemas.attestto.org/cr/driving/v1'
const CR_IDENTITY_CONTEXT = 'https://schemas.attestto.org/cr/identity/v1'
const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'

/** Context URL per credential type (defaults to CR_DRIVING_CONTEXT) */
const CREDENTIAL_CONTEXT: Record<string, string> = {
  IdentityVC: CR_IDENTITY_CONTEXT,
}

/** Property name in credentialSubject for each credential type (null = flat spread) */
const CREDENTIAL_TYPE_PROPERTY: Record<string, string | null> = {
  DrivingLicense: 'license',
  TheoreticalTestResult: 'theoreticalTest',
  PracticalTestResult: 'practicalTest',
  MedicalFitnessCredential: 'fitness',
  VehicleRegistration: 'vehicle',
  VehicleTechnicalReview: 'technicalReview',
  CirculationRights: 'circulationRights',
  SOATCredential: 'insurance',
  DriverIdentity: 'driverIdentity',
  TrafficViolation: 'violation',
  AccidentReport: 'accident',
  IdentityVC: null,  // flat claims — spread directly onto credentialSubject
}

export class VCIssuer {
  private config: Required<IssuerConfig>

  constructor(config: IssuerConfig) {
    this.config = {
      did: config.did,
      privateKey: typeof config.privateKey === 'string'
        ? new TextEncoder().encode(config.privateKey)
        : config.privateKey,
      algorithm: config.algorithm ?? 'Ed25519',
      keyId: config.keyId ?? '#key-1',
    }
  }

  /**
   * Issue a signed Verifiable Credential
   */
  async issue(options: IssueOptions): Promise<VerifiableCredential> {
    const now = new Date().toISOString()
    const credentialId = options.id ?? `urn:uuid:${crypto.randomUUID()}`

    // Build the credential subject
    const propertyName = CREDENTIAL_TYPE_PROPERTY[options.type]
    if (propertyName === undefined) {
      throw new Error(`Unknown credential type: ${options.type}`)
    }

    const credentialSubject: Record<string, unknown> = {
      id: options.subjectDid,
    }

    // Null property = flat spread (IdentityVC), string = wrapper property (driving types)
    if (propertyName === null) {
      Object.assign(credentialSubject, options.claims)
    } else if (options.claims[propertyName]) {
      Object.assign(credentialSubject, options.claims)
    } else {
      credentialSubject[propertyName] = options.claims
    }

    // Select the domain context based on credential type
    const domainContext = CREDENTIAL_CONTEXT[options.type] ?? CR_DRIVING_CONTEXT

    // Build the unsigned credential
    const credential: VerifiableCredential = {
      '@context': [W3C_VC_CONTEXT, domainContext],
      id: credentialId,
      type: ['VerifiableCredential', options.type],
      issuer: options.issuerInfo
        ? { id: this.config.did, ...options.issuerInfo }
        : this.config.did,
      issuanceDate: now,
      credentialSubject: credentialSubject as VerifiableCredential['credentialSubject'],
    }

    if (options.expirationDate) {
      credential.expirationDate = options.expirationDate
    }

    if (options.credentialStatus) {
      credential.credentialStatus = options.credentialStatus
    }

    // Sign the credential
    credential.proof = await this.createProof(credential)

    return credential
  }

  /**
   * Create a linked data proof for the credential
   */
  private async createProof(credential: VerifiableCredential): Promise<Proof> {
    const now = new Date().toISOString()

    // Serialize the credential (without proof) for signing
    const { proof: _, ...unsignedCredential } = credential
    const message = new TextEncoder().encode(JSON.stringify(unsignedCredential))

    // Sign
    const privateKey = this.config.privateKey instanceof Uint8Array
      ? this.config.privateKey
      : new TextEncoder().encode(this.config.privateKey)

    const signature = sign(message, privateKey, this.config.algorithm)

    return {
      type: this.config.algorithm === 'Ed25519' ? 'Ed25519Signature2020' : 'EcdsaSecp256r1Signature2019',
      created: now,
      verificationMethod: `${this.config.did}${this.config.keyId}`,
      proofPurpose: 'assertionMethod',
      proofValue: toBase64url(signature),
    }
  }

  /**
   * Issue a credential as a JWT (alternative to linked data proof)
   */
  async issueJwt(options: IssueOptions): Promise<string> {
    const credential = await this.issue({ ...options })
    // Remove the LD proof — JWT is the proof
    delete credential.proof

    const privateKey = this.config.privateKey instanceof Uint8Array
      ? this.config.privateKey
      : new TextEncoder().encode(this.config.privateKey)

    // Import key for jose
    const alg = this.config.algorithm === 'Ed25519' ? 'EdDSA' : 'ES256'
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      privateKey,
      this.config.algorithm === 'Ed25519'
        ? { name: 'Ed25519' }
        : { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    )

    const jwt = await new SignJWT({ vc: credential })
      .setProtectedHeader({
        alg,
        kid: `${this.config.did}${this.config.keyId}`,
      })
      .setIssuer(this.config.did)
      .setSubject(options.subjectDid)
      .setIssuedAt()
      .sign(cryptoKey)

    return jwt
  }

  /** Get the issuer DID */
  get did(): string {
    return this.config.did
  }
}

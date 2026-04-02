/**
 * Core types for the CR VC SDK
 */

/** Supported credential types from cr-vc-schemas */
export type CredentialType =
  | 'DrivingLicense'
  | 'TheoreticalTestResult'
  | 'PracticalTestResult'
  | 'MedicalFitnessCredential'
  | 'VehicleRegistration'
  | 'VehicleTechnicalReview'
  | 'CirculationRights'
  | 'SOATCredential'
  | 'DriverIdentity'
  | 'TrafficViolation'
  | 'AccidentReport'

/** W3C Verifiable Credential envelope */
export interface VerifiableCredential {
  '@context': string[]
  id: string
  type: ['VerifiableCredential', ...string[]]
  issuer: string
  issuanceDate: string
  expirationDate?: string
  credentialSubject: {
    id: string
    [key: string]: unknown
  }
  credentialStatus?: CredentialStatus
  proof?: Proof
}

/** W3C StatusList2021 entry */
export interface CredentialStatus {
  id: string
  type: 'StatusList2021Entry'
  statusPurpose: 'revocation' | 'suspension'
  statusListIndex: string
  statusListCredential: string
}

/** Linked Data Proof or JWT proof */
export interface Proof {
  type: string
  created: string
  verificationMethod: string
  proofPurpose: string
  proofValue?: string
  jws?: string
}

/** Issuer configuration */
export interface IssuerConfig {
  /** DID of the issuer (e.g. did:web:cosevi.attestto.id) */
  did: string
  /** Private key for signing (Ed25519 or P-256) */
  privateKey: Uint8Array | string
  /** Key algorithm */
  algorithm?: 'Ed25519' | 'ES256'
  /** Key ID (fragment of the DID, e.g. #key-1) */
  keyId?: string
}

/** Verification result */
export interface VerificationResult {
  /** Whether the credential is valid */
  valid: boolean
  /** Checks performed and their results */
  checks: VerificationCheck[]
  /** Errors encountered */
  errors: string[]
  /** Warnings (non-fatal issues) */
  warnings: string[]
}

/** Individual verification check */
export interface VerificationCheck {
  check: string
  passed: boolean
  message?: string
}

/** Options for issuing a credential */
export interface IssueOptions {
  /** Credential type */
  type: CredentialType
  /** DID of the subject (holder) */
  subjectDid: string
  /** Credential subject data (matches the schema for the type) */
  claims: Record<string, unknown>
  /** Optional expiration date (ISO 8601) */
  expirationDate?: string
  /** Optional credential status for revocation */
  credentialStatus?: CredentialStatus
  /** Optional credential ID (auto-generated if not provided) */
  id?: string
}

/** Options for verifying a credential */
export interface VerifyOptions {
  /** Check expiration date */
  checkExpiration?: boolean
  /** Check credential status (revocation) */
  checkStatus?: boolean
  /** Expected credential type */
  expectedType?: CredentialType
  /** Expected issuer DID */
  expectedIssuer?: string
}

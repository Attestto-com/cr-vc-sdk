/**
 * VCVerifier — Verify Verifiable Credentials
 *
 * Usage:
 * ```ts
 * import { VCVerifier } from '@attestto-com/cr-vc-sdk'
 *
 * const verifier = new VCVerifier()
 *
 * const result = await verifier.verify(credential, {
 *   checkExpiration: true,
 *   expectedType: 'DrivingLicense',
 *   expectedIssuer: 'did:web:cosevi.attestto.id',
 * })
 *
 * if (result.valid) {
 *   console.log('Credential is valid')
 * } else {
 *   console.log('Errors:', result.errors)
 * }
 * ```
 */

import { verify as verifySignature, fromBase64url } from './keys.js'
import type { VerifiableCredential, VerificationResult, VerificationCheck, VerifyOptions } from './types.js'

const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
const CR_DRIVING_CONTEXT = 'https://schemas.attestto.org/cr/driving/v1'

/** Public key resolver — given a DID + key ID, returns the public key */
export type PublicKeyResolver = (did: string, keyId: string) => Promise<{
  publicKey: Uint8Array
  algorithm: 'Ed25519' | 'ES256'
} | null>

export interface VerifierConfig {
  /** Function to resolve public keys from DIDs */
  resolvePublicKey?: PublicKeyResolver
}

export class VCVerifier {
  private resolvePublicKey?: PublicKeyResolver

  constructor(config?: VerifierConfig) {
    this.resolvePublicKey = config?.resolvePublicKey
  }

  /**
   * Verify a Verifiable Credential
   */
  async verify(
    credential: VerifiableCredential,
    options: VerifyOptions = {}
  ): Promise<VerificationResult> {
    const checks: VerificationCheck[] = []
    const errors: string[] = []
    const warnings: string[] = []

    // 1. Check structure
    this.checkStructure(credential, checks, errors)

    // 2. Check context
    this.checkContext(credential, checks, errors)

    // 3. Check credential type
    if (options.expectedType) {
      this.checkType(credential, options.expectedType, checks, errors)
    }

    // 4. Check issuer
    if (options.expectedIssuer) {
      this.checkIssuer(credential, options.expectedIssuer, checks, errors)
    }

    // 5. Check expiration
    if (options.checkExpiration !== false) {
      this.checkExpiration(credential, checks, errors, warnings)
    }

    // 6. Check issuance date
    this.checkIssuanceDate(credential, checks, errors)

    // 7. Verify proof/signature
    if (credential.proof && this.resolvePublicKey) {
      await this.checkProof(credential, checks, errors)
    } else if (credential.proof && !this.resolvePublicKey) {
      warnings.push('Proof present but no public key resolver configured — signature not verified')
    } else if (!credential.proof) {
      warnings.push('No proof present — credential is unsigned')
    }

    // 8. Check credential status (revocation) — placeholder
    if (options.checkStatus && credential.credentialStatus) {
      warnings.push('Status check requested but StatusList2021 verification not yet implemented')
    }

    const valid = errors.length === 0

    return { valid, checks, errors, warnings }
  }

  /**
   * Verify a credential with a known public key (no resolver needed)
   */
  async verifyWithKey(
    credential: VerifiableCredential,
    publicKey: Uint8Array,
    algorithm: 'Ed25519' | 'ES256' = 'Ed25519',
    options: VerifyOptions = {}
  ): Promise<VerificationResult> {
    const resolver: PublicKeyResolver = async () => ({ publicKey, algorithm })
    const verifier = new VCVerifier({ resolvePublicKey: resolver })
    return verifier.verify(credential, options)
  }

  private checkStructure(
    credential: VerifiableCredential,
    checks: VerificationCheck[],
    errors: string[]
  ): void {
    const hasContext = Array.isArray(credential['@context']) && credential['@context'].length > 0
    checks.push({ check: 'structure.context', passed: hasContext })
    if (!hasContext) errors.push('Missing or invalid @context')

    const hasType = Array.isArray(credential.type) && credential.type.includes('VerifiableCredential')
    checks.push({ check: 'structure.type', passed: hasType })
    if (!hasType) errors.push('Missing VerifiableCredential in type array')

    const hasIssuer = typeof credential.issuer === 'string' && credential.issuer.startsWith('did:')
    checks.push({ check: 'structure.issuer', passed: hasIssuer })
    if (!hasIssuer) errors.push('Missing or invalid issuer DID')

    const hasSubject = credential.credentialSubject?.id != null
    checks.push({ check: 'structure.subject', passed: hasSubject })
    if (!hasSubject) errors.push('Missing credentialSubject.id')

    const hasIssuanceDate = typeof credential.issuanceDate === 'string'
    checks.push({ check: 'structure.issuanceDate', passed: hasIssuanceDate })
    if (!hasIssuanceDate) errors.push('Missing issuanceDate')
  }

  private checkContext(
    credential: VerifiableCredential,
    checks: VerificationCheck[],
    errors: string[]
  ): void {
    const hasW3C = credential['@context'].includes(W3C_VC_CONTEXT)
    checks.push({ check: 'context.w3c', passed: hasW3C })
    if (!hasW3C) errors.push(`Missing W3C VC context: ${W3C_VC_CONTEXT}`)

    const hasCR = credential['@context'].includes(CR_DRIVING_CONTEXT)
    checks.push({ check: 'context.cr-driving', passed: hasCR })
    if (!hasCR) errors.push(`Missing CR driving context: ${CR_DRIVING_CONTEXT}`)
  }

  private checkType(
    credential: VerifiableCredential,
    expectedType: string,
    checks: VerificationCheck[],
    errors: string[]
  ): void {
    const hasType = credential.type.includes(expectedType)
    checks.push({ check: 'type.expected', passed: hasType, message: expectedType })
    if (!hasType) errors.push(`Expected credential type "${expectedType}" not found`)
  }

  private checkIssuer(
    credential: VerifiableCredential,
    expectedIssuer: string,
    checks: VerificationCheck[],
    errors: string[]
  ): void {
    const matches = credential.issuer === expectedIssuer
    checks.push({ check: 'issuer.expected', passed: matches, message: expectedIssuer })
    if (!matches) errors.push(`Expected issuer "${expectedIssuer}", got "${credential.issuer}"`)
  }

  private checkExpiration(
    credential: VerifiableCredential,
    checks: VerificationCheck[],
    errors: string[],
    warnings: string[]
  ): void {
    if (!credential.expirationDate) {
      checks.push({ check: 'expiration', passed: true, message: 'No expiration date set' })
      return
    }

    const expiry = new Date(credential.expirationDate)
    const now = new Date()
    const isValid = expiry > now

    checks.push({ check: 'expiration', passed: isValid, message: credential.expirationDate })
    if (!isValid) errors.push(`Credential expired on ${credential.expirationDate}`)

    // Warn if expiring within 30 days
    const thirtyDays = 30 * 24 * 60 * 60 * 1000
    if (isValid && (expiry.getTime() - now.getTime()) < thirtyDays) {
      warnings.push(`Credential expires soon: ${credential.expirationDate}`)
    }
  }

  private checkIssuanceDate(
    credential: VerifiableCredential,
    checks: VerificationCheck[],
    errors: string[]
  ): void {
    if (!credential.issuanceDate) return

    const issued = new Date(credential.issuanceDate)
    const now = new Date()
    // Allow 5 minute clock skew
    const fiveMinutes = 5 * 60 * 1000
    const isValid = issued.getTime() <= (now.getTime() + fiveMinutes)

    checks.push({ check: 'issuanceDate.notFuture', passed: isValid })
    if (!isValid) errors.push(`Credential issuance date is in the future: ${credential.issuanceDate}`)
  }

  private async checkProof(
    credential: VerifiableCredential,
    checks: VerificationCheck[],
    errors: string[]
  ): Promise<void> {
    if (!credential.proof || !this.resolvePublicKey) {
      checks.push({ check: 'proof.signature', passed: false, message: 'No proof or resolver' })
      errors.push('Cannot verify proof')
      return
    }

    // Parse verification method to get DID and key ID
    const verificationMethod = credential.proof.verificationMethod
    const hashIndex = verificationMethod.lastIndexOf('#')
    const did = hashIndex > 0 ? verificationMethod.substring(0, hashIndex) : verificationMethod
    const keyId = hashIndex > 0 ? verificationMethod.substring(hashIndex) : '#key-1'

    // Resolve public key
    const resolved = await this.resolvePublicKey(did, keyId)
    if (!resolved) {
      checks.push({ check: 'proof.keyResolution', passed: false, message: `Could not resolve key for ${did}` })
      errors.push(`Could not resolve public key for ${verificationMethod}`)
      return
    }

    checks.push({ check: 'proof.keyResolution', passed: true })

    // Reconstruct the signed message (credential without proof)
    const { proof: _, ...unsignedCredential } = credential
    const message = new TextEncoder().encode(JSON.stringify(unsignedCredential))

    // Verify signature
    const signature = fromBase64url(credential.proof.proofValue ?? '')
    const isValid = verifySignature(message, signature, resolved.publicKey, resolved.algorithm)

    checks.push({ check: 'proof.signature', passed: isValid })
    if (!isValid) errors.push('Invalid signature')
  }
}

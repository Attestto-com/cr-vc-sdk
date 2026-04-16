/**
 * @attestto/cr-vc-sdk
 *
 * SDK for issuing and verifying Verifiable Credentials
 * in the Costa Rica SSI driving ecosystem.
 *
 * Schemas: https://github.com/Attestto-com/cr-vc-schemas
 */

export { VCIssuer } from './issuer.js'
export { VCVerifier } from './verifier.js'
export type { PublicKeyResolver, VerifierConfig } from './verifier.js'
export { generateKeyPair, sign, verify, toBase64url, fromBase64url, toHex } from './keys.js'
export type { KeyPair } from './keys.js'
export type {
  CredentialType,
  VerifiableCredential,
  CredentialStatus,
  Proof,
  IssuerConfig,
  VerificationResult,
  VerificationCheck,
  IssueOptions,
  VerifyOptions,
} from './types.js'

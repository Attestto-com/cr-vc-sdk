/**
 * SOC-174 Class B — `#key-1` is one DID method's convention, not a default.
 *
 * This repo carries a STANDALONE verifier: it does not depend on
 * `@attestto/vc-sdk`, so a fix there does not reach here (recorded in
 * `CLAUDE.md` after SOC-16 and SOC-19 were closed on exactly that wrong
 * assumption and stayed live for weeks). The same defect therefore has to be
 * fixed twice, on purpose, and this file is the local proof.
 *
 * **Verifying — the serious half.** When a proof's `verificationMethod` carried
 * no fragment, the verifier substituted `#key-1` and resolved THAT key. A proof
 * that named no key at all was checked against a key the VERIFIER chose; if the
 * subject's document happened to contain a `#key-1`, it verified. Which key
 * signed a credential is the proof's statement to make, never the verifier's to
 * fill in.
 *
 * **Signing.** `VCIssuer` defaulted `keyId` to `#key-1` for a DID of any
 * method. `did:sns` names its owner key `#solana-key`, `did:key` and `did:jwk`
 * use `#0`, a `did:web` document names whatever it names. The default produced
 * a well-formed credential naming a verification method the issuer's own
 * document does not contain, which a verifier reports as an ordinary signature
 * failure — indistinguishable from a wrong key.
 */
import { describe, it, expect } from 'vitest'
import { VCIssuer } from '../src/issuer'
import { VCVerifier } from '../src/verifier'
import type { VerifiableCredential } from '../src/types'

const KEY = new Uint8Array(32).fill(7)
const SNS_DID = 'did:sns:alice.crbank'
const SNS_VM = `${SNS_DID}#solana-key`

const signed = (verificationMethod: string): VerifiableCredential =>
  ({
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    'type': ['VerifiableCredential'],
    'issuer': SNS_DID,
    'issuanceDate': '2026-01-01T00:00:00Z',
    'credentialSubject': { id: 'did:key:zSubject' },
    'proof': {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00Z',
      proofPurpose: 'assertionMethod',
      verificationMethod,
      proofValue: 'z'.repeat(80),
    },
  }) as VerifiableCredential

describe('signing — the key id is stated, never assumed', () => {
  it('VCIssuer refuses to construct without a key id', () => {
    expect(() => new VCIssuer({ did: SNS_DID, privateKey: KEY })).toThrow(/keyId/i)
  })

  it('VCIssuer refuses a key id that is not a fragment', () => {
    expect(
      () => new VCIssuer({ did: SNS_DID, privateKey: KEY, keyId: 'solana-key' }),
    ).toThrow(/#/)
  })

  it('VCIssuer keeps the key id it was given', () => {
    const issuer = new VCIssuer({ did: SNS_DID, privateKey: KEY, keyId: '#solana-key' })
    expect(issuer.keyId).toBe('#solana-key')
  })
})

describe('verifying — the proof names its key, or it does not verify', () => {
  it('asks for the exact fragment the proof names', async () => {
    const asked: Array<{ did: string; keyId: string }> = []
    const verifier = new VCVerifier({
      resolvePublicKey: async (did: string, keyId: string) => {
        asked.push({ did, keyId })
        return null
      },
    })

    await verifier.verify(signed(SNS_VM))
    expect(asked).toContainEqual({ did: SNS_DID, keyId: '#solana-key' })
  })

  it('never even asks for a key when the proof names none', async () => {
    // Asserting only `valid === false` would be vacuous: the fixture's
    // proofValue is nonsense, so the signature check fails either way and the
    // test would pass with the defect fully present. The behavioural claim is
    // that resolution is not ATTEMPTED, because choosing a key IS the defect.
    let calls = 0
    const verifier = new VCVerifier({
      resolvePublicKey: async () => {
        calls++
        return { publicKey: KEY, algorithm: 'Ed25519' as const }
      },
    })

    const result = await verifier.verify(signed(SNS_DID))
    expect(calls).toBe(0)
    expect(result.valid).toBe(false)
    expect(result.errors.join(' ')).toMatch(/fragment/i)
  })
})

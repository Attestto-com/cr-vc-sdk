import { describe, it, expect } from 'vitest'
import { generateKeyPair, sign, verify, toBase64url, fromBase64url, toHex } from '../src/index.js'

describe('Key Management', () => {
  describe('Ed25519', () => {
    it('generates a valid key pair', () => {
      const keys = generateKeyPair('Ed25519')
      expect(keys.algorithm).toBe('Ed25519')
      expect(keys.privateKey).toHaveLength(32)
      expect(keys.publicKey).toHaveLength(32)
    })

    it('signs and verifies a message', () => {
      const keys = generateKeyPair('Ed25519')
      const message = new TextEncoder().encode('hello world')
      const signature = sign(message, keys.privateKey, 'Ed25519')

      expect(verify(message, signature, keys.publicKey, 'Ed25519')).toBe(true)
    })

    it('rejects tampered message', () => {
      const keys = generateKeyPair('Ed25519')
      const message = new TextEncoder().encode('hello world')
      const signature = sign(message, keys.privateKey, 'Ed25519')

      const tampered = new TextEncoder().encode('hello tampered')
      expect(verify(tampered, signature, keys.publicKey, 'Ed25519')).toBe(false)
    })

    it('rejects wrong key', () => {
      const keys1 = generateKeyPair('Ed25519')
      const keys2 = generateKeyPair('Ed25519')
      const message = new TextEncoder().encode('hello world')
      const signature = sign(message, keys1.privateKey, 'Ed25519')

      expect(verify(message, signature, keys2.publicKey, 'Ed25519')).toBe(false)
    })
  })

  describe('ES256 (P-256)', () => {
    it('generates a valid key pair', () => {
      const keys = generateKeyPair('ES256')
      expect(keys.algorithm).toBe('ES256')
      expect(keys.privateKey.length).toBeGreaterThan(0)
      expect(keys.publicKey.length).toBeGreaterThan(0)
    })

    it('signs and verifies a message', () => {
      const keys = generateKeyPair('ES256')
      const message = new TextEncoder().encode('hello world')
      const signature = sign(message, keys.privateKey, 'ES256')

      expect(verify(message, signature, keys.publicKey, 'ES256')).toBe(true)
    })
  })

  describe('Encoding utilities', () => {
    it('roundtrips base64url', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128])
      const encoded = toBase64url(original)
      const decoded = fromBase64url(encoded)

      expect(decoded).toEqual(original)
    })

    it('produces valid hex', () => {
      const bytes = new Uint8Array([0, 15, 255])
      expect(toHex(bytes)).toBe('000fff')
    })
  })
})

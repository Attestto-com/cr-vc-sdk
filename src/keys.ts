/**
 * Key management utilities
 *
 * Supports Ed25519 (default) and P-256 (ES256) key pairs.
 * Uses @noble/curves for cryptographic operations — no native dependencies.
 */

import { ed25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import { randomBytes } from '@noble/hashes/utils'

export interface KeyPair {
  algorithm: 'Ed25519' | 'ES256'
  publicKey: Uint8Array
  privateKey: Uint8Array
}

/**
 * Generate a new key pair
 */
export function generateKeyPair(algorithm: 'Ed25519' | 'ES256' = 'Ed25519'): KeyPair {
  if (algorithm === 'Ed25519') {
    const privateKey = randomBytes(32)
    const publicKey = ed25519.getPublicKey(privateKey)
    return { algorithm, publicKey, privateKey }
  }

  const privateKey = p256.utils.randomPrivateKey()
  const publicKey = p256.getPublicKey(privateKey, false)
  return { algorithm, publicKey, privateKey }
}

/**
 * Sign a message with a private key
 */
export function sign(message: Uint8Array, privateKey: Uint8Array, algorithm: 'Ed25519' | 'ES256' = 'Ed25519'): Uint8Array {
  if (algorithm === 'Ed25519') {
    return ed25519.sign(message, privateKey)
  }

  const sig = p256.sign(message, privateKey)
  return sig.toCompactRawBytes()
}

/**
 * Verify a signature
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  algorithm: 'Ed25519' | 'ES256' = 'Ed25519'
): boolean {
  try {
    if (algorithm === 'Ed25519') {
      return ed25519.verify(signature, message, publicKey)
    }

    return p256.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

/**
 * Encode bytes to base64url (no padding)
 */
export function toBase64url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Decode base64url to bytes
 */
export function fromBase64url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

/**
 * Encode bytes to hex
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

# @attestto-com/cr-vc-sdk

SDK para emitir y verificar Credenciales Verificables basado en los esquemas propuestos para el ecosistema vial de Costa Rica.

> **Propuesta tecnica** de [Attestto Open](https://attestto.org). Los esquemas y tipos de credenciales son una propuesta abierta a revision por las instituciones competentes (COSEVI, MICITT, DGEV). Ver [cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas) para detalles.
>
> **5 lineas de codigo para emitir una licencia de conducir digital.**

## Instalacion

```bash
npm install @attestto-com/cr-vc-sdk
```

## Uso rapido

### Emitir una licencia de conducir digital

```typescript
import { VCIssuer, generateKeyPair } from '@attestto-com/cr-vc-sdk'

const keys = generateKeyPair()
const issuer = new VCIssuer({
  did: 'did:web:cosevi.attestto.id',
  privateKey: keys.privateKey,
})

const license = await issuer.issue({
  type: 'DrivingLicense',
  subjectDid: 'did:web:maria.attestto.id',
  expirationDate: '2032-04-01T23:59:59Z',
  claims: {
    licenseNumber: 'CR-2026-045678',
    categories: ['B', 'A1'],
    issueDate: '2026-04-01',
    expiresAt: '2032-04-01',
    status: 'active',
    points: 12,
    bloodType: 'O+',
    restrictions: ['lentes correctivos'],
    issuingAuthority: 'did:web:cosevi.attestto.id',
  },
})
// license es una VC firmada, lista para entregar al wallet del ciudadano
```

### Verificar una credencial

```typescript
import { VCVerifier } from '@attestto-com/cr-vc-sdk'

const verifier = new VCVerifier()
const result = await verifier.verifyWithKey(license, keys.publicKey, 'Ed25519', {
  checkExpiration: true,
  expectedType: 'DrivingLicense',
  expectedIssuer: 'did:web:cosevi.attestto.id',
})

if (result.valid) {
  console.log('Licencia valida')
} else {
  console.log('Errores:', result.errors)
}
```

### Emitir resultado de prueba teorica

```typescript
const testResult = await issuer.issue({
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
    testCenterName: 'Academia Tica de Conduccion S.A.',
    examVersionHash: 'sha256:e7f8a9b0c1d2e3f4...',
    totalQuestions: 40,
    correctAnswers: 35,
    proctoring: {
      method: 'remote-biometric',
      telemetryHash: 'sha256:1a2b3c4d...',
      livenessVerified: true,
      identityVerified: true,
    },
  },
})
```

### Verificar con resolver de claves publicas

```typescript
const verifier = new VCVerifier({
  resolvePublicKey: async (did, keyId) => {
    // Resolver la clave publica desde el DID document
    // En produccion: fetch did:web document o consultar SAS
    const response = await fetch(`https://${did.replace('did:web:', '')}/.well-known/did.json`)
    const didDoc = await response.json()
    // ... extraer la clave publica
    return { publicKey, algorithm: 'Ed25519' }
  },
})

const result = await verifier.verify(credential, {
  checkExpiration: true,
  expectedType: 'DrivingLicense',
})
```

## Tipos de credenciales soportados

| Tipo | Descripcion | Emisor tipico |
|---|---|---|
| `DrivingLicense` | Licencia de conducir digital (mDL) | COSEVI/DGEV |
| `TheoreticalTestResult` | Prueba teorica (online o presencial) | DGEV / proveedor certificado |
| `PracticalTestResult` | Prueba practica (conduccion real) | DGEV / proveedor certificado |
| `MedicalFitnessCredential` | Dictamen medico de aptitud | Consultorio autorizado |
| `VehicleRegistration` | Registro vehicular (placa) | Registro Nacional |
| `VehicleTechnicalReview` | Revision tecnica (RTV) | Centro RTV |
| `CirculationRights` | Derechos de circulacion (marchamo) | Hacienda / Municipalidad |
| `SOATCredential` | Seguro obligatorio (SOAT) | INS |
| `DriverIdentity` | Identidad del conductor | TSE / DGME / banco / COSEVI |
| `TrafficViolation` | Multa de transito | COSEVI |
| `AccidentReport` | Parte de accidente | COSEVI / INS |

## API

### `VCIssuer`

```typescript
const issuer = new VCIssuer({
  did: string,           // DID del emisor
  privateKey: Uint8Array, // Clave privada Ed25519 o P-256
  algorithm?: 'Ed25519' | 'ES256', // Default: Ed25519
  keyId?: string,        // Default: '#key-1'
})

// Emitir VC con linked data proof
const vc = await issuer.issue(options: IssueOptions)

// Emitir VC como JWT
const jwt = await issuer.issueJwt(options: IssueOptions)
```

### `VCVerifier`

```typescript
const verifier = new VCVerifier({
  resolvePublicKey?: (did, keyId) => Promise<{ publicKey, algorithm } | null>
})

// Verificar con resolver
const result = await verifier.verify(vc, options?: VerifyOptions)

// Verificar con clave conocida (sin resolver)
const result = await verifier.verifyWithKey(vc, publicKey, algorithm, options?)
```

### `generateKeyPair`

```typescript
const keys = generateKeyPair('Ed25519') // o 'ES256'
// keys.publicKey: Uint8Array
// keys.privateKey: Uint8Array
// keys.algorithm: 'Ed25519' | 'ES256'
```

## Esquemas

Los esquemas JSON-LD estan en: [Attestto-com/cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas)

## Ecosistema

| Repositorio | Que hace |
|---|---|
| [cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas) | Esquemas JSON-LD (11 tipos de VC) |
| [did-sns-spec](https://github.com/Attestto-com/did-sns-spec) | Especificacion del metodo `did:sns` |
| [wallet-identity-resolver](https://github.com/Attestto-com/wallet-identity-resolver) | Resolucion de identidad on-chain |
| [credential-wallet-connector](https://github.com/Attestto-com/credential-wallet-connector) | Descubrimiento de wallets |
| [vLEI-Solana-Bridge](https://github.com/Attestto-com/vLei-Solana-Bridge) | Puente vLEI → Solana |

## Licencia

Apache 2.0

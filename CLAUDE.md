# @attestto/cr-vc-sdk — Operating Rules

> SDK for issuing and verifying Verifiable Credentials in the Costa Rica SSI driving ecosystem.

## Stack

- TypeScript (ESM + CJS dual export)
- Build: tsup (+ tsc for type declarations)
- Tests: Vitest
- Lint: ESLint with @typescript-eslint
- Crypto: @noble/curves, @noble/hashes, jose
- Node >= 18

## Commands

- `pnpm install` -- install deps
- `pnpm build` -- build with tsup
- `pnpm test` -- run tests (vitest)
- `pnpm test:watch` -- run tests in watch mode
- `pnpm test:coverage` -- run tests with coverage
- `pnpm lint` -- lint src and tests (eslint)
- `pnpm typecheck` -- type-check without emitting
- `pnpm clean` -- remove dist and coverage

## Architecture

- Wraps `@attestto/vc-sdk` with CR-specific typed credential helpers
- 11 credential types: DrivingLicense, TheoreticalTestResult, PracticalTestResult, MedicalFitnessCredential, VehicleRegistration, VehicleTechnicalReview, CirculationRights, SOATCredential, DriverIdentity, TrafficViolation, AccidentReport
- JSON-LD schemas live in `schemas/` and ship with the package
- Schema definitions come from the sibling `cr-vc-schemas` repo

## Rules

- This is a public `@attestto/*` package -- changes must not break downstream consumers
- Ship tests with every change
- Credential types and schemas are proposals open to institutional review (COSEVI, MICITT, DGEV) -- document any schema changes clearly
- Do not add CORTEX-specific rules here -- this repo has its own conventions
- Do not run `pnpm dev` -- user owns the dev server

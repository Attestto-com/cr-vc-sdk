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

- CR-specific typed credential helpers, with **its own** `VCIssuer` / `VCVerifier`
- 🔴 **This package does NOT depend on `@attestto/vc-sdk`.** Corrected 2026-08-06: `package.json`
  lists no `@attestto/*` dependency, and `src/verifier.ts` is a standalone implementation. The
  earlier "wraps `@attestto/vc-sdk`" wording was wrong and it was load-bearing — SOC-16 and SOC-19
  were closed on 2026-07-19 with the remediation "bump `@attestto/vc-sdk` and inherit the fix".
  There was nothing to inherit through, so both defects were still live eighteen days later.
  **A fix in `vc-sdk` does not reach this package. Fix it here too.**
- The verifier is not a copy to delete: it enforces the `cr/driving/v1` and `cr/identity/v1`
  JSON-LD contexts and CR credential types, which the generic SDK has no concept of. The *generic*
  half is duplicated, and `tests/verifier-parity.spec.ts` is the control that keeps the two from
  diverging silently. If you harden verification in either package, that file must still pass.
- 22 credential types across 6 domains: vehicular (11), citizen identity (4), notarial (2), signing (2), competency (2), agreement (1)
- JSON-LD schemas live in `schemas/` and ship with the package
- Schema definitions come from the sibling `cr-vc-schemas` repo

## Rules

- This is a public `@attestto/*` package -- changes must not break downstream consumers
- Ship tests with every change
- Credential types and schemas are proposals open to institutional review (COSEVI, MICITT, DGEV) -- document any schema changes clearly
- Do not add CORTEX-specific rules here -- this repo has its own conventions
- Do not run `pnpm dev` -- user owns the dev server

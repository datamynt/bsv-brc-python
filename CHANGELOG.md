# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-04-08

### Changed
- Migrated cryptographic primitives from `coincurve` + `ecdsa` to the official
  [`bsv-sdk`](https://pypi.org/project/bsv-sdk/) (`py-sdk`). This consolidates
  the secp256k1, signing, and key derivation surface onto the upstream BSV
  Python SDK and removes a layer of dependencies.

### Added
- GitHub Actions CI workflow running the test suite on Python 3.10–3.13.

### Internal
- Updated `CLAUDE.md` to reflect the new dependency surface.

## [0.1.0] - 2026-03-16

### Added
- Initial release.
- `bsv_brc.brc052` — BRC-42/43/52/53: identity certificates, ECDH key
  derivation, AES-256-GCM encryption, certificate signing and issuance.
- `bsv_brc.brc094` — BRC-94: Schnorr proof of ECDH shared secrets,
  counterparty linkage.
- `bsv_brc.brc105` — BRC-105: HTTP 402 micropayment middleware (Starlette)
  and client.
- `bsv_brc.crypto` — shared BRC-42 / BRC-43 key derivation primitives.
- 63 tests covering all three BRC modules.

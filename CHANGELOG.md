# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-09

### Changed (BREAKING)
- Pivoted `bsv-brc` from a parallel BRC-103/104 implementation to a set
  of **framework adapters around the official `bsv.auth`** module shipped
  in `bsv-sdk==2.0.0b1`. The previously bundled `bsv_brc.brc103.*` and
  `bsv_brc.brc104.core.preimage` modules duplicated functionality that
  already exists upstream and have been removed.
- `bsv-sdk` minimum bumped to `2.0.0b1` (pre-release). Install with
  `pip install --pre bsv-brc` or pin explicitly.
- Added `typing_extensions` as a direct dependency to work around a
  missing transitive declaration in `bsv-sdk==2.0.0b1`.

### Removed
- `bsv_brc.brc103` package (use `bsv.auth` from `bsv-sdk` directly).
- `bsv_brc.brc104.core.preimage` (use
  `bsv.auth.clients.auth_fetch.AuthFetch` / the bsv.auth response
  serializer). `bsv_brc.brc104.core.headers` is retained for adapter use.
- Tests covering the removed modules.

### Notes
- BRC-52, BRC-94 and BRC-105 are unchanged and remain the unique value
  of this package alongside the upcoming ASGI/WSGI adapters for
  `bsv.auth`.
- Wire-format audit against `bsv.auth` found one divergence inherited
  from `py-middleware`: response preimage must include the
  `authorization` header. This will be addressed in the new adapter
  layer rather than in the deleted `preimage.py`.

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

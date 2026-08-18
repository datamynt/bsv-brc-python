# bsv-brc-python — BRC ecosystem modernization review

_Sist oppdatert: 2026-08-17 · Agent: dsh-peck/deepseek-v4-flash_

This document maps `bsv-brc` against the **current** BRC standards
repository (`bsv-blockchain/BRCs`, spec set current to 2026-08-12, 150+
standards up to BRC-228) and lays out what modernization means for this
library. It is the basis for the 0.5.0 release; items below are prioritized.

## 1. Where the library stands (verified)

Baseline on this round: the full suite (**197 tests**) passes on
Python 3.14 with the latest `bsv-sdk` **2.3.3** (the pin floor was 2.1.3).
It remains the only OSS Python package providing the *server side* of the
BSV stack: BRC-22/24 overlay node, BRC-103/104 auth adapter, BRC-105 402
payments, BRC-52 certificates, BRC-94 Schnorr proofs, BRC-87 names.
Consumers in the wild (this monorepo): `peck-certifier` (brc052),
`peck-web` (brc104 AuthMiddleware + brc052/crypto), `bsv-compat` (bitcom).

## 2. What matured/changed in the BRC ecosystem since 0.4.0 (2026-06)

### 2.1 Removed / corrected misconceptions in this repo's docs

The "out of scope" claims in `README.md`/`CHANGELOG.md` are **stale and
factually wrong** against the current BRC index:

| Claim in repo | Reality (2026-08 BRC index) |
|---|---|
| "BRC-101: aspirational, no normative behavior" | BRC-101 = *Diverse Facilitators and URL Protocols for SHIP and SLAP Overlay Advertisements* (overlays/0101.md) — has content. |
| "BRC-108: no Mandala/BRC-92/107 token base" | BRC-108 = *Identity-Linked Token Protocol* (tokens/0108.md) — links token state to the identity ledger of BRC-42/52/53. |
| "BRC-116: needs an external sCrypt toolchain" | BRC-116 = *Wallet Permissions and Counterparty Trust* (wallet/0116.md) — pure wallet/wire concept, nothing sCrypt. |
| "BRC-88: not pursued" | Still correct — SHIP/SLAP remains out of the overlay.social model (GASP + state roots instead). |

These have been corrected in this release (see `README.md`, `CLAUDE.md`).

### 2.2 New standards directly relevant to this library

**Payments — the 402 family matured (payments/README.md):**
- **BRC-105** remains the *primary* BSV-native HTTP monetization framework.
- **BRC-118** — Multipart body transport for BRC-105 (large chained BEEFs
  blow past header limits; 8 KB auto-switch; backward-compatible, header
  transport not deprecated). Direct extension of our `brc105` module.
- **BRC-120** — x402 (frozen external spec, stateless settlement-gated).
- **BRC-121** — Simple 402 (small BSV-specific profile; `x-bsv-sats`,
  `x-bsv-server`, `x-bsv-beef`, `x-bsv-nonce`, `x-bsv-time`, `x-bsv-vout`;
  replay via wallet `isMerge`). Reference impls: `@bsv/402-pay`,
  `go-402-pay`, browser extension.
- **BRC-125** — PeerPay URI scheme for BRC-29 payments.
- **BRC-228** — Unlinkable payments under the identity paradigm (sender
  side profile of BRC-29, ephemeral per-payment keys).

**Authentication — request auth beyond BRC-103:**
- **BRC-138** — Single-Use Signed Proofs for Request Authentication: a
  one-shot, expiry-bound, action-bound signed proof; login and one-shot
  actions without a full BRC-103 session. Reference impl `@bsv/auth`
  (TS). **→ implemented in this release as `bsv_brc.brc138`, proven
  byte-compatible with `@bsv/auth` in both directions.**

**Transactions — BEEF family:**
- **BRC-96** — BEEF V2 Txid-only extension (bandwidth win for ancestors).
- **BRC-158** — Outpoint BEEF.
- **BRC-95** — Atomic BEEF (already in use by overlay/105 paths).

**Overlay:**
- **BRC-76** — Graph Aware Sync Protocol (GASP) — this is the sync the
  repo's roadmap already names; still unimplemented.
- **BRC-136** — Block-Anchored Overlay Synchronization via BASM
  (block-aligned sparse Merkle trees) — a newer, block-anchored sync
  alternative worth comparing with GASP.
- **BRC-35** — Layered KVStore — still gated in this repo; unchanged.

**Identity-adjacent (worth a look for peck's identity stack):**
- BRC-77/78 (message signing / portable encrypted messages — py-sdk has
  BRC-77 already), BRC-140/154/157 (backups), BRC-169 (universal handle
  addressing), BRC-145 (registry-free typed content anchor), BRC-146
  (access gates), BRC-147/150/159/160 (1Sat ordinals).

### 2.3 SDK floor

`bsv-sdk` is at **2.3.3**; the repo floor is `>=2.1.3`. The full suite
passes on 2.3.3, so the floor can be raised to `>=2.2.0` (or 2.3.x) at the
next release without code changes — recommended so downstream gets the
latest primitives (the two py-sdk bugs in `docs/upstream/`, filed as
py-sdk#158/#159, persist in 2.3.3 and are worked around here already).

## 3. What "modernization" means for this library — prioritized roadmap

Legend: 🟢 done this release · 🟡 next · 🔵 later

### Auth & payments (the web ergonomics core)

- 🟢 **BRC-138 single-use proofs** (`bsv_brc.brc138`) — new module; login
  primitive for peck-style apps; interoperable with `@bsv/auth` out of the
  box (same default protocol `[2, "bsv auth proof"]`).
- 🟡 **BRC-118 multipart transport in `brc105`** — server-side extraction
  (`x-bsv-payment-transports` advertising + multipart body parse) and
  client-side switch at 8 KB. Needed the moment agents chain payments
  (llm-gateway/peck-host use cases).
- 🟡 **BRC-121 simple 402 profile** — a `x-bsv-*` header-only alternative
  that works *without* BRC-103 (the repo's current 105 middleware demands
  auth first). Good for public, stateless monetized endpoints.
- 🔵 BRC-120 x402 conformance layer (thin — mostly a no-op alias onto 105
  semantics) and BRC-125 PeerPay URI parsing.

### Overlay node

- 🟡 **BRC-96 txid-only BEEF / BRC-158 outpoint BEEF** — bandwidth
  optimization for `/submit` and `/lookup` answers when peers opt in.
- 🔵 **BRC-76 GASP peer sync** (roadmap item, still open) and/or **BRC-136
  BASM** — the repo's per-topic Merkle state root is already the right
  primitive; anchoring the root on-chain + syncing via GASP is the
  remaining piece.
- 🔵 BRC-35 KVStore client once a live `tm_kvstore` exists to interop
  against.

### Hygiene

- 🟡 Raise `bsv-sdk` floor, add py3.14 to CI matrix (suite already green),
  fix the stale BRC-101/108/116 claims (done in docs this release).
- 🔵 File the remaining readiness of `docs/upstream/` reports (both already
  filed — #158/#159 — mark README accordingly).

## 4. Decision points for Thomas

1. **BRC-118 vs BRC-121 first?** Both extend `brc105`. BRC-118 = breathing
   room for chained payments (agents); BRC-121 = stateless public paywalls
   without auth. The repo's README frames 105 as building on 103 — BRC-121
   deliberately drops that dependency.
2. **GASP vs BASM** for the sync roadmap — worth one design note before
   implementing either.
3. **peck-identity alignment**: `identity.peck.to` is described as "BRC-101
   identity resolution" in the architecture docs, but official BRC-101 is
   SHIP/SLAP advertisement URLs. Identity resolution in the BRC dir lives
   elsewhere (BRC-169 handles; BRC-68 trust anchors; certificates BRC-52).
   Worth a correction sweep in peck-docs and identity-services naming.

## 5. What landed in 0.5.0 (this release)

- `bsv_brc.brc138` — BRC-138 single-use signed proofs: create / verify /
  check, memory + SQLite single-use stores, Starlette ASGI middleware.
- `crypto.keys.derive_signing_public_key` — the verifier-side counterpart
  of BRC-43 signing key derivation.
- Cross-implementation interop harness (`examples/brc138_interop/`) +
  pinned regression vectors (`tests/test_brc138_interop.py`) certified
  against `@bsv/auth` 0.1.3 / `@bsv/sdk` 2.4.1.
- Stale BRC-101/108/116 claims corrected in README/CLAUDE; documented
  gap analysis (this file).
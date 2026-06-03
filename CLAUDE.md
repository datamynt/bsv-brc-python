# bsv-brc-python

Python implementations of BSV BRC protocols. Opensource under Open BSV License.
Supersedes standalone brc52-python (now included as brc052 subpackage).

## Packages

- **BRC-52** (`bsv_brc.brc052`) — Identity certificates, AES-256-GCM, signing/issuance
- **BRC-94** (`bsv_brc.brc094`) — Schnorr proof of ECDH shared secrets (BRC-69 + BRC-93 fix)
- **BRC-103/104** (`bsv_brc.brc104`) — ASGI mutual-auth adapter wrapping `bsv.auth.Peer`
- **BRC-105** (`bsv_brc.brc105`) — HTTP 402 micropayment middleware + client
- **BRC-22** (`bsv_brc.brc22`) — server-side overlay topic submission (`/submit`)
- **BRC-24** (`bsv_brc.brc24`) — server-side lookup services / feed (`/lookup`)
- **BRC-87** (`bsv_brc.brc87`) — `tm_`/`ls_` overlay name validation
- **overlay** (`bsv_brc.overlay`) — `OverlayEngine`: a runnable overlay node
- **integration** (`bsv_brc.integration`) — `build_brc_app` stacks auth + payments
- **crypto** (`bsv_brc.crypto`) — BRC-42/43 key derivation (shared primitives)

## Design philosophy — DO NOT duplicate py-sdk

`bsv-sdk` (py-sdk) already provides the *client* side of overlay
(`LookupResolver`, `SHIPBroadcaster`, `TopicBroadcaster`,
`AdmittanceInstructions`, `OverlayAdminTokenTemplate`, `Historian`),
BEEF parse/serialize, SPV, certificates/keyrings, and `LocalKVStore`.
bsv-brc's value is the **server side + web ergonomics** py-sdk leaves
open. Reuse py-sdk dataclasses; never redefine them. This is the same
lesson as the 0.2.0 pivot (which deleted a duplicate BRC-103/104).

## Structure

```
src/bsv_brc/
  brc052/          — AES-GCM, certificate binary/signing/issuance
  brc094/          — Schnorr proof generation/verification, counterparty linkage
  brc104/          — bsv.auth ASGI adapter (AuthMiddleware), wire/headers
  brc105/          — NonceManager, middleware (Starlette), client, pricing
  brc22/           — TopicManager ABC, TopicEngine, adapters/asgi (/submit)
  brc24/           — LookupService ABC, OutputRef, wire (binary output-list)
  brc87.py         — tm_/ls_ overlay name validation (pure stdlib)
  bitcom.py        — Bitcoin-Schema OP_RETURN (B/MAP/AIP) build+parse+AIP
  overlay/         — OverlayEngine, storage (in-mem + SQLite), topic_root, client (OverlayClient), adapters/asgi
  ../docs/upstream/ — ready-to-file py-sdk bug reports (2 confirmed in 2.1.3+HEAD)
  integration.py   — build_brc_app, BRC-29 internalize verifier, PathPricing
  crypto/          — BRC-42 ECDH, BRC-43 key derivation
```

Goal: bsv-brc = OSS foundation for building social apps on overlay
(an open-source peck.to). `examples/social_feed.py` is the reference
seed. overlay.social model = chain anchor + overlay read layer
(GASP-sync + per-topic Merkle roots, NOT SHIP/SLAP — so no BRC-88) +
BRC-100 identity + 3 write channels (token-state / input-script-data /
OP_RETURN) + BRC-77 verifiability. py-sdk already has BRC-77
(`bsv.signed_message`) and UHRP (`bsv.storage`) — compose, don't dup.

Lookup wire: binary output-list = format py-sdk *intends* (its
`_parse_binary_response` has a read_var_int vs read_var_int_num bug,
present through 2.1.3 + HEAD → file upstream, report in docs/upstream/).
BEEF-backed answers ship via the JSON path (`Accept: application/json`).

Per-topic state root: VERIFIED against overlay.peck.to /state (canonical
peck-social-overlay §3.2 algo = sha256 of sorted "txid:vout" set joined
by \n; empty=sha256(""); matches live e3b0c442... empty-root). Implemented
in overlay/topic_root.py + OverlayEngine.topic_root. Gate OPEN. Still
gated: binary trailing-BEEF layout, BRC-35 (overlay.peck.to has no
tm_kvstore), on-chain anchoring + GASP sync.

bsv-sdk pinned >=2.1.3 (was 2.0.0b1 beta). Probe live overlay with
`curl https://overlay.peck.to/{state,listTopicManagers,listLookupServiceProviders}`.

Infra-bootstrap idea (Thomas): OSS libs can default to peck-hosted
endpoints (overlay.peck.to live; storage.peck.to/headers.peck.to not in
the domain map yet) so apps bootstrap on peck infra, swappable to
self-host. Confirm which endpoints are live before defaulting to them.

> Note: tests run in `.venv2` (has `bsv-sdk==2.0.0b1` with `bsv.auth`).
> `.venv`/`venv` are stale and lack `bsv.auth` — ignore them.

## Run tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[starlette,dev]"
pytest -v
```

## Dependencies

`bsv-sdk` on PyPI (source: [`bsv-blockchain/py-sdk`](https://github.com/bsv-blockchain/py-sdk))
— BSV protocol primitives: secp256k1, signing, key derivation.
Note: not to be confused with `@bsv/sdk` on npm, which is the TypeScript SDK.

`pycryptodomex` — AES-256-GCM.

Optional: `starlette` (middleware extra).

## Design

- Framework-agnostic core, Starlette middleware as optional extra
- Compatible with @bsv/sdk TypeScript and brc52-python
- BRC-105 middleware mirrors @bsv/payment-express-middleware API
- verify_payment callback = integration point for wallet.internalizeAction()

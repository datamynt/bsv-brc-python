# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Overlay CLIENT** (`bsv_brc.overlay.OverlayClient`) — the consumer
  side, defaulting to `overlay.peck.to`. `submit(beef, topics)` (JSON
  `x-topics` array + octet-stream BEEF) returns a parsed STEAK with
  `.admitted` and an opt-in `NoAdmissionError` (the silent
  200-but-rejected trap); `lookup(service, query)` parses the
  BEEF-backed output-list (beef as byte-array *or* base64, txid from the
  AtomicBEEF prefix); `state()` / `topic_state()` read `GET /state`; and
  `verify_state(topic, outpoints)` checks the node's published state root
  against a local `state_root()`. Pure I/O-free builders/parsers
  (`build_submit_headers`, `parse_steak`, `parse_lookup_answer`,
  `parse_state`) are exposed for async apps to wire into their own HTTP
  client; the bundled client is stdlib-`urllib` only (no new deps) and
  takes a `fetch` override for testing/httpx. Verified live against
  overlay.peck.to. Closes the gap where every Python service hand-rolled
  its own overlay consumer.

## [0.3.0] - 2026-06-02

### Added
- **Overlay node — be the server, not just a client** (`bsv-sdk` ships
  only the overlay client side):
  - **BRC-22** (`bsv_brc.brc22`) — `TopicManager` (define which outputs
    your topic admits), `TopicEngine` (parse BEEF, run each hosted
    manager, return the topic-keyed STEAK map), and `adapters.asgi` with
    a mountable `SubmitASGIApp` plus a redirect-free `make_submit_route`.
  - **BRC-24** (`bsv_brc.brc24`) — `LookupService` (the read side: index
    admitted outputs, answer queries), `OutputRef`, and a binary
    output-list serializer matching the format py-sdk's `LookupResolver`
    intends to read (py-sdk 2.0.0b1's parser has a `read_var_int` vs
    `read_var_int_num` bug — filed-worthy — so the included round-trip
    test decodes with the corrected reader).
  - **`bsv_brc.overlay`** — `OverlayEngine` composes topic managers +
    lookup services + an `OverlayStorage` into one submit/lookup engine
    with admit/spend event dispatch; `create_overlay_app` exposes
    `/submit` + `/lookup` as a Starlette app.
  - **Production-ready node**: `SqliteOverlayStorage` (persistent,
    alongside the in-memory reference) and **BEEF-backed answers** — a
    client that sends `Accept: application/json` to `/lookup` gets each
    output's full BEEF (base64) and can reconstruct the transaction
    without a second fetch; the default binary answer stays py-sdk
    compatible. Added an `[overlay]` extra.
  - Admittance/answer types (`AdmittanceInstructions`, `TaggedBEEF`,
    `LookupQuestion`, `LookupAnswer`) are reused from `bsv.overlay_tools`,
    not redefined.
  - **BRC-87** (`bsv_brc.brc87`) — `validate_topic_name` /
    `validate_service_name` (+ `is_valid_*` and `validate_overlay_name`)
    enforce the `tm_`/`ls_` master rules so a bad name fails fast instead
    of silently failing to interoperate.
  - **Per-topic state root** (`bsv_brc.overlay.topic_root` +
    `OverlayEngine.topic_root` / `topic_roots`) — the canonical
    peck-social-overlay root over a topic's live (unspent) outpoint set:
    `sha256` of the deduped, lexicographically-sorted
    `"<txid>:<vout>"` strings joined by newlines (empty set →
    `sha256("")`). **Verified to match `overlay.peck.to`'s `GET /state`
    `stateRoot` exactly** (the empty-set value `e3b0c442…` is asserted
    against the live overlay in the test suite), so a bsv-brc node and
    the live peck overlay agree on a topic's root for the same UTXO set.
    `create_overlay_app` now also serves `GET /state`
    (`{"status","topics":[{"topic","count","stateRoot"}]}`) — the same
    verifiable contract `overlay.peck.to` exposes (`make_state_route`,
    `OverlayEngine.topic_state` / `topic_states`).

### Upstream
- Filed-ready bug reports for two `bsv-sdk` (py-sdk) defects found while
  building on it, in `docs/upstream/` — both confirmed present in the
  latest PyPI `2.1.3` and `master` HEAD (not just our pinned beta):
  `LookupResolver._parse_binary_response` uses `read_var_int` (bytes)
  where it needs `read_var_int_num` (int), crashing on any binary
  output-list answer; and `ProtoWallet.internalize_action` parses
  AtomicBEEF as a raw transaction, risking a corrupt broadcast.
- **Integration layer** (`bsv_brc.integration`) — `build_brc_app` stacks
  BRC-103/104 auth under BRC-105 payments in the correct order;
  `make_internalize_verifier` / `build_internalize_args` provide the
  BRC-29 derivation prefix/suffix → `wallet.internalize_action` mapping
  (the hardest hand-rolled step) as a ready callback; `PathPricing`,
  `get_identity` and `get_payment` are small request-side ergonomics.
- **BRC-104 ASGI adapter released** — `bsv_brc.brc104.adapters.asgi`
  (`AuthMiddleware`) wrapping `bsv.auth.Peer` for Starlette/FastAPI/
  FastHTML, built in 0.2.x but previously unreleased, now ships.
- `py.typed` marker so downstream type-checkers see the library's hints.
- Top-level re-exports + `__all__` on `bsv_brc`; integration helpers are
  lazily exposed so `import bsv_brc` still works without the
  `starlette` extra.
- `examples/full_app.py` — a fake-free server stacking auth + payments +
  a BRC-22 topic.
- `examples/social_feed.py` — a complete ~150-line social overlay node
  (`tm_posts` topic + `ls_posts` feed + an HTML `/feed`): the seed of an
  open-source peck.to built entirely on this library.

### Hardened (adversarial multi-agent review of the overlay stack)
- **Interop**: `/submit` now accepts the `X-Topics` format py-sdk's
  `TopicBroadcaster` actually sends — a comma-separated string — as well
  as a JSON array. Previously every real py-sdk submission was rejected.
- **Correctness**: a coin a transaction spends on-chain is now always
  marked spent and fires `output_spent`, even when the topic manager
  lists it in `coins_to_retain` (retention is a history concern, not
  liveness; matches canonical @bsv/overlay). Fixes stale state lingering
  in current-state feeds.
- **Concurrency**: `OverlayEngine.submit` serializes its check-then-act
  under an `asyncio.Lock` (an async topic manager could otherwise let
  two concurrent submits double-spend a coin); `SqliteOverlayStorage`
  reads now take the write lock (lock-free reads on the shared
  connection raced); the BEEF-backed lookup `resolve` runs off the event
  loop via `asyncio.to_thread`.
- **Safety**: request bodies are capped (default 32 MiB, configurable;
  413 on overflow) instead of buffering unboundedly; `/submit` and
  `/lookup` no longer reflect internal exception text to clients (logged
  server-side); `X-Topics` is capped at 64 topics and the unknown-topic
  error no longer echoes the requested list; `serialize_output_list`
  rejects non-32-byte txids instead of silently corrupting the stream.
- **Docs**: `build_brc_app`'s default `StaticPricing(0)` clarified (no
  payment ≠ open access — auth still required); `make_internalize_verifier`
  documents that the wallet must accept AtomicBEEF (the bsv-sdk 2.0.0b1
  `ProtoWallet` does not — tracked upstream).

### Notes
- Still deferred: the BRC-35 Global KVStore client (its PushDrop field
  layout can't be verified — `overlay.peck.to` doesn't host
  `tm_kvstore`); on-chain anchoring of the topic state root + GASP peer
  sync (the root format itself is now verified, but anchoring/sync are a
  larger piece); the binary lookup-answer's trailing BEEF (BEEF ships via
  the JSON path). SHIP/SLAP (BRC-88) is intentionally **not** pursued —
  overlay.social federates via state roots + GASP, not SHIP/SLAP.
- Out of scope and documented as such: BRC-101 (aspirational, no
  normative behavior), BRC-108 (no Mandala/BRC-92/107 token base in
  either package), BRC-116 (needs an external sCrypt/scrypt-ord
  toolchain).

### Changed
- Bumped the `bsv-sdk` floor from the pre-release `2.0.0b1` to the
  latest stable `2.1.3`. Full suite stays green. (Note: the two upstream
  py-sdk bugs in `docs/upstream/` persist at 2.1.3 / HEAD, so this bump
  is unrelated to them.)

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

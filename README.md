# bsv-brc

[![PyPI version](https://img.shields.io/pypi/v/bsv-brc.svg)](https://pypi.org/project/bsv-brc/)
[![Python versions](https://img.shields.io/pypi/pyversions/bsv-brc.svg)](https://pypi.org/project/bsv-brc/)
[![Tests](https://github.com/datamynt/bsv-brc-python/actions/workflows/test.yml/badge.svg)](https://github.com/datamynt/bsv-brc-python/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](LICENSE)

Python implementations of [BSV BRC protocols](https://bsv.brc.dev).
The higher-level protocol companion to [py-sdk](https://github.com/bsv-blockchain/py-sdk) (`bsv-sdk` on PyPI).

While `bsv-sdk` handles transactions, keys, and SPV — `bsv-brc` implements the
protocol layer: identity certificates, verifiable key linkage, HTTP mutual
auth + micropayments, and the **server-side overlay machinery** py-sdk leaves
open (it ships only the overlay *client* side).

| Package | BRC | What |
|---------|-----|------|
| `bsv_brc.brc052` | [BRC-42/43/52/53](https://bsv.brc.dev/peer-to-peer/0052) | Identity certificates, ECDH key derivation, AES-256-GCM |
| `bsv_brc.brc094` | [BRC-94](https://bsv.brc.dev/key-derivation/0094) | Verifiable ECDH shared secrets via Schnorr proof |
| `bsv_brc.brc104` | [BRC-103/104](https://bsv.brc.dev/peer-to-peer/0104) | ASGI mutual-auth adapter over `bsv.auth` |
| `bsv_brc.brc105` | [BRC-105](https://bsv.brc.dev/payments/0105) | HTTP 402 micropayment middleware + client |
| `bsv_brc.brc138` | [BRC-138](https://bsv.brc.dev/peer-to-peer/0138) | Single-use signed proofs — login in one request (`@bsv/auth`-compatible) |
| `bsv_brc.brc22` | [BRC-22](https://bsv.brc.dev/overlays/0022) | **Server-side** overlay topic submission (`/submit`) |
| `bsv_brc.brc24` | [BRC-24](https://bsv.brc.dev/overlays/0024) | **Server-side** lookup services — the feed (`/lookup`) |
| `bsv_brc.brc87` | [BRC-87](https://bsv.brc.dev/overlays/0087) | `tm_`/`ls_` overlay name validation |
| `bsv_brc.overlay` | — | `OverlayEngine` (run a node) + `OverlayClient` (talk to one) |
| `bsv_brc.integration` | — | `build_brc_app`: auth + payments pre-stacked |

## Install

```bash
pip install bsv-brc
```

For Starlette/FastHTML middleware:

```bash
pip install "bsv-brc[starlette]"
```

## Quick examples

### Ship a whole BRC app — auth + payments in a few lines

```python
from bsv_brc import build_brc_app, PathPricing
from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import ProtoWallet

wallet = ProtoWallet(PrivateKey())  # load a persisted key in production

app = build_brc_app(
    your_asgi_app,
    wallet=wallet,                              # server identity + payment settle
    pricing=PathPricing({"/premium": 100}),     # 100 sats on /premium, rest free
)
# Stacks BRC-103/104 auth under BRC-105 payments. The default
# verify_payment maps the client's BRC-29 derivation prefix/suffix to
# wallet.internalize_action() for you — no hand-rolling.
```

See [`examples/full_app.py`](examples/full_app.py) for a complete,
fake-free server with auth, payments and a BRC-22 overlay topic.

### Be an overlay node — submit + a queryable feed

`bsv-sdk` lets you *talk to* an overlay (`LookupResolver`,
`TopicBroadcaster`); `bsv-brc` lets you *be* one. Define a topic
(what gets admitted) and a lookup service (the feed), and serve both:

```python
from bsv_brc.brc22 import TopicManager, AdmittanceInstructions
from bsv_brc.brc24 import LookupService, OutputRef
from bsv_brc.overlay import OverlayEngine
from bsv_brc.overlay.adapters.asgi import create_overlay_app

class PostsTopic(TopicManager):
    def identify_admissible_outputs(self, beef, previous_coins):
        # Decode with Transaction.from_beef(beef); pick which outputs to admit.
        return AdmittanceInstructions(outputs_to_admit=[0], coins_to_retain=[])

class PostsFeed(LookupService):
    def __init__(self): self.posts = []
    def output_admitted(self, topic, txid, output_index, locking_script, satoshis):
        self.posts.insert(0, OutputRef(txid, output_index, context=locking_script))
    def lookup(self, question):
        return self.posts[: (question.query or {}).get("limit", 20)]

engine = OverlayEngine(
    topic_managers={"tm_posts": PostsTopic()},
    lookup_services={"ls_posts": PostsFeed()},
)
app = create_overlay_app(engine)  # POST /submit, POST /lookup
```

See [`examples/social_feed.py`](examples/social_feed.py) for a complete
~150-line social feed (the seed of an open-source peck.to).

### Talk to an overlay — submit, read, verify

The consumer side, defaulting to `overlay.peck.to` (swappable):

```python
from bsv_brc import OverlayClient

overlay = OverlayClient()  # defaults to https://overlay.peck.to

result = overlay.submit(beef_bytes, ["tm_posts"], require_admission=True)
# result.admitted -> bool; NoAdmissionError on a 200-but-rejected submit

posts = overlay.lookup("ls_posts", {"limit": 20})   # -> [LookupOutput(txid, beef, ...)]
state = overlay.state()                              # [{topic, count, stateRoot}]
ok = overlay.verify_state("tm_posts", outpoints)     # local state_root == node's
```

Async apps can use the pure `build_submit_headers` / `parse_steak` /
`parse_lookup_answer` / `parse_state` helpers with their own HTTP client.

### BRC-138: Authenticate a request in one shot (login, no handshake)

Single-use signed proofs: prove you hold an identity key in one request,
without a BRC-103 session. Interoperates with the reference TypeScript
`@bsv/auth` out of the box (same default protocol `[2, "bsv auth proof"]`):

```python
from bsv_brc.brc138 import MemorySingleUseStore, create_auth_proof, verify_auth_proof

# Client (e.g. a browser wallet): sign a "login" proof toward the server key
proof = create_auth_proof(client_identity_privkey, server_identity_pubkey, "login")
# ...transmit proof.to_dict() (signature = byte values, per spec)...

# Server: shape -> action -> freshness -> signature -> single-use, atomically
identity = verify_auth_proof(
    server_identity_privkey, proof, "login",
    single_use_store=MemorySingleUseStore(),  # SqliteSingleUseStore for persistence
)
# identity == client public key -> caller provably holds the key
```

See [`examples/brc138_auth.py`](examples/brc138_auth.py), and
`examples/brc138_interop/` for the Python ⇄ TypeScript byte-compat proof.

### BRC-105: Accept micropayments on any endpoint

```python
from starlette.applications import Starlette
from bsv_brc.brc105 import PaymentMiddleware, NonceManager, StaticPricing

nonce_manager = NonceManager(secret=b"your-server-secret")

async def verify_payment(payment, identity_key):
    # Call wallet.internalize_action() or your own verification
    ...

app = Starlette(routes=[...])
app.add_middleware(
    PaymentMiddleware,
    nonce_manager=nonce_manager,
    pricing=StaticPricing(100),  # 100 satoshis per request
    verify_payment=verify_payment,
)
```

### BRC-94: Prove an ECDH shared secret without revealing private keys

```python
from bsv_brc.brc094 import generate_proof, verify_proof

# Prover side
shared_secret, R, S_prime, z = generate_proof(my_private_key, their_public_key)

# Verifier side — no private keys needed
is_valid = verify_proof(prover_public_key, counterparty_public_key, shared_secret, R, S_prime, z)
```

### BRC-52: Issue an identity certificate

```python
from bsv_brc.brc052 import issue, make_certificate_type

cert = issue(
    certifier_private_key=certifier_key,
    cert_type=make_certificate_type("example.com/identity/v1"),
    subject_key=subject_pubkey_hex,
    field_values={"email": "alice@example.com"},
    serial_number=serial,
    encrypted_field_keys=encrypted_keys_from_client,
)
```

## Roadmap

- [x] BRC-103/104 — Mutual authentication (ASGI adapter over `bsv.auth`)
- [x] BRC-138 — Single-use signed proofs (login in one request, `@bsv/auth`-compatible)
- [x] BRC-22 — Server-side overlay topic submission (`/submit`)
- [x] BRC-24 + `OverlayEngine` — Lookup services + a runnable overlay node
- [ ] BRC-35 — Global KVStore over overlay (pending byte-exact interop check)
- [x] BEEF-backed lookup answers (JSON) + `SqliteOverlayStorage`
- [x] BRC-87 — `tm_`/`ls_` name validation
- [x] Per-topic state root + `GET /state` endpoint — **matches `overlay.peck.to` `/state`**
- [x] Overlay `OverlayClient` (submit / lookup / state / verify) — defaults to `overlay.peck.to`
- [x] Optional SPV verify on submit (`OverlayEngine(verify_tx=...)`, injectable ChainTracker)
- [ ] BRC-118 multipart transport + BRC-121 simple-402 profile for `brc105`
- [ ] paymail (→ bsv-compat), peck-anchor client + headers.peck.to ChainTracker (peck-infra lib)
- [ ] BRC-76 GASP peer sync / BRC-136 BASM + on-chain root anchoring

See [`docs/MODERNIZATION.md`](docs/MODERNIZATION.md) for the full BRC
ecosystem gap analysis (payments 402 family, BEEF v2, overlay sync).

Out of scope today: SHIP/SLAP (BRC-88) — the overlay.social model is
GASP/Merkle-roots, not SHIP/SLAP; BRC-120 x402 conformance (frozen external
spec) and the 1Sat token series (BRC-147/150/159/160) — separate concerns.

## Development

```bash
git clone https://github.com/datamynt/bsv-brc-python.git
cd bsv-brc-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[starlette,dev]"
pytest -v  # 235 tests
```
```

## License

[Open BSV License](LICENSE)

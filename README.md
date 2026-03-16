# bsv-brc

Python implementations of [BSV BRC protocols](https://bsv.brc.dev).
The higher-level protocol companion to [bsv-sdk](https://pypi.org/project/bsv-sdk/).

While `bsv-sdk` handles transactions, keys, and SPV — `bsv-brc` implements the
protocol layer: identity certificates, verifiable key linkage, and HTTP micropayments.

| Package | BRC | What |
|---------|-----|------|
| `bsv_brc.brc052` | [BRC-42/43/52/53](https://bsv.brc.dev/peer-to-peer/0052) | Identity certificates, ECDH key derivation, AES-256-GCM |
| `bsv_brc.brc094` | [BRC-94](https://bsv.brc.dev/key-derivation/0094) | Verifiable ECDH shared secrets via Schnorr proof |
| `bsv_brc.brc105` | [BRC-105](https://bsv.brc.dev/payments/0105) | HTTP 402 micropayment middleware + client |

## Install

```bash
pip install bsv-brc
```

For Starlette/FastHTML middleware:

```bash
pip install "bsv-brc[starlette]"
```

## Quick examples

### BRC-105: Accept micropayments on any endpoint

```python
from starlette.applications import Starlette
from bsv_brc.brc105 import PaymentMiddleware, NonceManager, StaticPricing

nonce_manager = NonceManager(secret=b"your-server-secret")

async def verify_payment(payment, identity_key):
    # Call wallet.internalizeAction() or your own verification
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

- [ ] BRC-103/104 — Mutual authentication (peer-to-peer + HTTP transport)
- [ ] BRC-108 — Identity-linked tokens
- [ ] BRC-88 — SHIP/SLAP overlay network sync
- [ ] BRC-101 — Extended overlay facilitators (WebSocket, auth+payment URLs)
- [ ] BRC-116 — Proof-of-Indexing Hash-to-Mint

## Development

```bash
git clone https://github.com/datamynt/bsv-brc-python.git
cd bsv-brc-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[starlette,dev]"
pytest -v  # 63 tests
```

## License

[Open BSV License](LICENSE)

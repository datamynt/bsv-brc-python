# bsv-brc-python

Python implementations of BSV BRC protocols. Opensource under Open BSV License.
Supersedes standalone brc52-python (now included as brc052 subpackage).

## Packages

- **BRC-52** (`bsv_brc.brc052`) — Identity certificates, AES-256-GCM, signing/issuance
- **BRC-94** (`bsv_brc.brc094`) — Schnorr proof of ECDH shared secrets (BRC-69 + BRC-93 fix)
- **BRC-105** (`bsv_brc.brc105`) — HTTP 402 micropayment middleware + client
- **crypto** (`bsv_brc.crypto`) — BRC-42/43 key derivation (shared primitives)

## Structure

```
src/bsv_brc/
  brc052/          — AES-GCM, certificate binary/signing/issuance
  brc094/          — Schnorr proof generation/verification, counterparty linkage
  brc105/          — NonceManager, middleware (Starlette), client, pricing
  crypto/          — BRC-42 ECDH, BRC-43 key derivation
```

## Run tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[starlette,dev]"
pytest -v
```

## Dependencies

bsv-sdk (BSV protocol primitives — secp256k1, signing, key derivation),
pycryptodomex (AES-256-GCM).
Optional: starlette (middleware extra).

## Design

- Framework-agnostic core, Starlette middleware as optional extra
- Compatible with @bsv/sdk TypeScript and brc52-python
- BRC-105 middleware mirrors @bsv/payment-express-middleware API
- verify_payment callback = integration point for wallet.internalizeAction()

# Examples

Runnable examples for `bsv-brc`. Each one is self-contained and small enough
to read in a single sitting.

## ⚠️ Demo only — read this first

**These examples use fake stubs** for the parts that require a real BSV
wallet. They demonstrate the *protocol flow*, not real cryptographic
verification. Specifically:

- `verify_payment` always accepts — production code must call your wallet's
  `internalizeAction()` (or equivalent) and return the real result.
- `build_payment` returns a hardcoded fake transaction — production code
  must call your wallet's `createAction()` to build a real signed payment.
- `get_identity_key` bypasses BRC-103 authentication for local testing —
  production code must use real BRC-103/104 mutual auth (coming in a future
  release of `bsv-brc`).

**Do not deploy these examples as-is.** They will accept any payment (or
none at all) and they will not protect you from anything. They exist so
you can see the shape of the API in 30 seconds without needing a wallet
running on your machine.

## brc105 — HTTP 402 micropayments

The `BRC-105` examples show the server and client sides of the 402 Payment
Required flow. The two scripts talk to each other over HTTP on
`127.0.0.1:8000`.

### Run

In one terminal:

```bash
pip install "bsv-brc[starlette]" uvicorn httpx
python examples/brc105_minimal_server.py
```

In another terminal:

```bash
python examples/brc105_client.py
```

### What you should see

Server side:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     127.0.0.1:xxxxx - "GET /data HTTP/1.1" 402 Payment Required
INFO:     127.0.0.1:xxxxx - "GET /data HTTP/1.1" 200 OK
```

Client side:
```
→ GET /data (no payment)
  ← 402
  challenge: 100 satoshis required
→ GET /data (with payment)
  ← 200
  body: {'data': 'hello, paying customer', 'satoshis_paid': 100}
  satoshis_paid header: 100
```

### What just happened

1. Client requested a paid endpoint without including a payment header.
2. Server's `PaymentMiddleware` saw no payment, generated a derivation
   prefix nonce, and returned `402 Payment Required` with the challenge
   in the response headers.
3. Client parsed the challenge, built a payment (fake, in this example),
   and retried the request with the `x-bsv-payment` header.
4. Server's middleware verified the nonce, called `verify_payment` (which
   in this demo always accepts), and let the request through to the
   handler.
5. Handler returned the response, and the middleware added an
   `x-bsv-payment-satoshis-paid` header to confirm the amount.

In a real deployment, steps 2 and 3 would involve actual BSV wallet
operations and the payment would be a signed transaction the server can
broadcast and verify on-chain.

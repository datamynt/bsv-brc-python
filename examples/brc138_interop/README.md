# BRC-138 interop check (Python ⇄ TypeScript reference)

Proves `bsv_brc.brc138` is byte-compatible with the canonical TypeScript
implementation for BRC-138, [`@bsv/auth`](https://www.npmjs.com/package/@bsv/auth)
(which wraps the `@bsv/sdk` BRC-100 wallet interface):

1. Python creates a proof → Node (`verifyAuthProof`) accepts it
2. Python creates a proof with a bound payload → Node accepts it
3. Node (`createAuthProof`) creates a proof → Python (`verify_auth_proof`) accepts it
4. Node creates a proof with a bound binary payload → Python accepts it

The pinned vectors from a certified run live in
`tests/test_brc138_interop.py` (a regression test that needs no Node), so the
byte-compatibility contract stays guarded in CI.

## Setup

```bash
cd examples/brc138_interop
npm install              # installs @bsv/auth + @bsv/sdk (see package.json)
cd ../..
python -m venv .venv && source .venv/bin/activate   # or reuse an existing venv
pip install -e ".[dev]"
```

## Run the live cross-implementation check

```bash
python examples/brc138_interop/run_interop.py
```

Expect:

```
[1/4] Python proof verified by @bsv/auth (Node): OK
[2/4] Python bound-payload proof verified by @bsv/auth (Node): OK
[3/4] Node proof verified by bsv_brc.brc138 (Python): OK
[4/4] Node bound-payload proof verified by bsv_brc.brc138 (Python): OK
ALL INTEROP CHECKS PASSED
```

## Re-capture pinned vectors (after upstream changes)

```bash
python examples/brc138_interop/capture_vectors.py
```

Paste the printed JSON into `tests/test_brc138_interop.py` (each vector is
re-certified against Node during capture — the script aborts if Node rejects
one).
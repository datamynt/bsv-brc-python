"""
BRC-104 signing pre-image construction.

NOT YET IMPLEMENTED. This is the most wire-compat-sensitive module in
the entire library. A single byte difference between this module's
output and the corresponding output from `@bsv/sdk` or
`bsv-blockchain/py-middleware` will cause every signature to fail
verification cross-implementation.

The pre-image is constructed (per BRC-104 spec) from:

  1. Request method (e.g., "GET", "POST")
  2. Request path + query string (e.g., "/api/data?id=42")
  3. Whitelisted headers in lexicographic order:
       - `authorization` (client + server)
       - `content-type` (client only — server skips it because
         middleware tends to mutate it with `; charset=utf-8`)
       - All `x-bsv-*` headers EXCEPT `x-bsv-auth-*`
  4. Request body bytes

The exact serialization (separator bytes, header line format,
whether names are lowercased before sorting, whether the body is
length-prefixed or appended raw) MUST match the reference
implementation byte-for-byte.

Implementation will be unblocked once we have either:
- Test vectors from `bsv-blockchain/py-middleware/django/transport.py`
- A live interop test against an `@bsv/sdk` server

See ROADMAP.md for the implementation plan.
"""

from __future__ import annotations

# Intentionally no implementation yet — see module docstring.

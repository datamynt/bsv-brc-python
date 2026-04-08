"""
BRC-104 framework adapters.

Each module in this subpackage is a thin wrapper that adapts a specific
Python web framework to the pure BRC-104 core in
`bsv_brc.brc104.core`. Adapters are intentionally small (~50 lines
each) so the heavy lifting stays in the core where it can be tested
without any framework installed.

Planned adapters:

- `asgi.py` — works with any ASGI app (Starlette, FastAPI, FastHTML,
  Litestar, Quart). NOT YET IMPLEMENTED.
- `django.py` — Django middleware class. NOT YET IMPLEMENTED.
- `flask.py` — Flask before_request/after_request hooks. NOT YET
  IMPLEMENTED.

Add a new adapter by:

  1. Translating your framework's request object into method, path,
     headers, and body.
  2. Calling the relevant `bsv_brc.brc104.core` functions.
  3. Translating the result back into your framework's response type.
"""

# LookupResolver cannot decode any binary output-list: `read_var_int()` (bytes) used instead of `read_var_int_num()` (int)

> Target: `bsv-blockchain/py-sdk` (`bsv-sdk` on PyPI).
> Confirmed in `2.0.0b1`, latest PyPI `2.1.3`, and `master` HEAD. No existing issue found.

## Summary

`HTTPSOverlayLookupFacilitator._parse_binary_response` in
`bsv/overlay_tools/lookup_resolver.py` calls `Reader.read_var_int()` — which
returns **raw bytes** — in three places where an **int** is required
(`read_var_int_num()`). The first use feeds the bytes into `range(...)`, so
decoding any binary (`application/octet-stream`) overlay lookup answer
immediately raises:

```
TypeError: 'bytes' object cannot be interpreted as an integer
```

Overlay lookup services commonly answer with the binary output-list format (the
SDK itself sends `X-Aggregation: yes` and branches on
`content-type == application/octet-stream`), so `LookupResolver.query()` /
`lookup()` cannot decode **any** binary output-list answer from a real overlay
host.

## Affected versions

- Reproduced on **2.0.0b1**.
- Offending code still present in latest PyPI release **2.1.3** (sdist inspected) and at **`master` HEAD**.

## Root cause

`bsv/overlay_tools/lookup_resolver.py`, `_parse_binary_response` (lines from the 2.1.3 sdist):

```python
172:    n_outpoints = reader.read_var_int()          # returns bytes, not int
175:    for _ in range(n_outpoints):                 # range(bytes) -> TypeError
176:        reader.read(32).hex()  # txid
177:        output_index = reader.read_var_int()     # bytes, not int
178:        context_length = reader.read_var_int()   # bytes, not int
...
        if context_length > 0:                       # bytes > 0 -> TypeError (if reached)
            context = reader.read(context_length)    # read(bytes) is also wrong
```

`Reader.read_var_int()` returns the raw VarInt bytes; `Reader.read_var_int_num()`
returns the decoded integer. The method needs the integer in all three spots.

```python
from bsv.utils import Reader, Writer
w = Writer(); w.write_var_int_num(5)
Reader(bytes(w.to_bytes())).read_var_int()      # -> b'\x05'  (bytes)
Reader(bytes(w.to_bytes())).read_var_int_num()  # -> 5        (int)
```

## Minimal reproduction

```python
from bsv.overlay_tools.lookup_resolver import HTTPSOverlayLookupFacilitator
from bsv.utils import Writer

w = Writer()
w.write_var_int_num(1)        # n_outpoints = 1
w.write(b'\x11' * 32)         # txid
w.write_var_int_num(0)        # output_index = 0
w.write_var_int_num(0)        # context_length = 0
w.write(b'\xde\xad\xbe\xef')  # trailing beef bytes
data = bytes(w.to_bytes())

HTTPSOverlayLookupFacilitator(allow_http=True)._parse_binary_response(data)
```

- **Expected:** returns `LookupAnswer(type="output-list", outputs=[LookupOutput(...)])`.
- **Actual:** `TypeError: 'bytes' object cannot be interpreted as an integer`.

## Suggested fix

```python
n_outpoints = reader.read_var_int_num()
for _ in range(n_outpoints):
    reader.read(32).hex()  # txid
    output_index = reader.read_var_int_num()
    context_length = reader.read_var_int_num()
    context = None
    if context_length > 0:
        context = reader.read(context_length)
    ...
```

Separately (out of scope for this crash fix, worth a follow-up): the method is a
"simplified implementation" that always sets `beef=b""` and never reconstructs
the per-output BEEF — cross-check the TypeScript SDK's `parseLookupAnswer` for
the full field layout.

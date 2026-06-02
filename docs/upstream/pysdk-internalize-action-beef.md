# `ProtoWallet.internalize_action` parses AtomicBEEF as a raw tx (`from_reader`, not BEEF-aware) — corrupts/broadcasts wrong bytes

> Target: `bsv-blockchain/py-sdk` (`bsv-sdk` on PyPI).
> Confirmed in `2.0.0b1`, latest PyPI `2.1.3`, and `master` HEAD (byte-identical). No existing issue found.

## Summary

`ProtoWallet.internalize_action` is documented to accept its `tx` argument as
**AtomicBEEF** (BRC-29), but the broadcast parse path decodes it as a **raw**
transaction with `Transaction.from_reader(...)` and never checks the BEEF magic
prefix `b"\x01\x00\xbe\xef"`. When you pass real BEEF bytes (as the interface
contract requires), the bytes are silently mis-decoded and a corrupt transaction
can be broadcast.

## Affected versions

- Reproduced on `bsv-sdk==2.0.0b1`.
- Still present at PyPI `2.1.3` (latest stable) and at `master` HEAD — the offending code is byte-for-byte identical across all three.

## The contract says BEEF

`bsv/wallet/wallet_interface.py`:

```python
AtomicBEEF = list[int]                       # line 32
...
def internalize_action(self, args, originator=None) -> InternalizeActionResult:
    """
    Args:
        args: Dictionary containing:
            - tx (AtomicBEEF or bytes): Transaction data in BEEF format    # line 821
    """
```

Both the type alias and the docstring (and BRC-29's `internalizeAction`) say
`tx` is BEEF.

## The offending code

`bsv/wallet/wallet_impl.py` — `internalize_action` delegates to
`_parse_transaction_for_broadcast`, which parses raw only:

```python
def _parse_transaction_for_broadcast(self, tx_bytes: bytes) -> dict:
    ...
    tx = Transaction.from_reader(Reader(tx_bytes))    # RAW only, no BEEF check
```

`_broadcast_with_arc` re-parses the same raw bytes the same way. Yet the **same
module** already has a BEEF-aware helper that is simply not on this path:

```python
def _parse_transaction(self, tx_bytes: bytes):
    if tx_bytes[:4] == b"\x01\x00\xbe\xef":  # BEEF magic
        return Transaction.from_beef(tx_bytes)
    else:
        return Transaction.from_reader(Reader(tx_bytes))
```

## Minimal reproduction (2.0.0b1)

```python
from bsv.keys import PrivateKey
from bsv.transaction import Transaction, TransactionOutput
from bsv.script.script import Script
from bsv.wallet.wallet_impl import ProtoWallet

tx = Transaction()
tx.add_output(TransactionOutput(locking_script=Script(b"\x6a\x04test"), satoshis=0))
beef = tx.to_beef()                       # AtomicBEEF, per the interface contract

w = ProtoWallet(PrivateKey())
res = w._parse_transaction_for_broadcast(beef)
print("parsed tx_hex starts:", res["tx_hex"][:20])
print("beef bytes starts   :", beef.hex()[:20])
```

Output — the "parsed" transaction begins with the BEEF magic `0100beef` instead
of a tx version `01000000`, i.e. `from_reader` read the BEEF header as a raw tx:

```
parsed tx_hex starts: 0100beef000101000000
beef bytes starts   : 0100beef000101000000
```

Calling the sibling `w._parse_transaction(beef)` decodes it correctly; the
broadcast path uses the wrong one.

## Expected vs actual

- **Expected:** `internalize_action({'tx': beef_data})` recognizes BEEF, decodes via `Transaction.from_beef`, and broadcasts the real underlying transaction.
- **Actual:** BEEF bytes are decoded as a raw tx via `from_reader`, yielding a corrupt `tx_hex` that is then handed to the broadcaster.

## Suggested fix

Route the broadcast parse path through the existing BEEF-aware helper, e.g.:

```python
def _parse_transaction_for_broadcast(self, tx_bytes: bytes) -> dict:
    if tx_bytes[:4] == b"\x01\x00\xbe\xef":      # BEEF magic
        tx = Transaction.from_beef(tx_bytes)
    else:
        tx = Transaction.from_reader(Reader(tx_bytes))
    ...
```

and likewise in `_broadcast_with_arc` (which also calls `from_reader` on the
same `tx_bytes`). Cleanest: route both through the existing `_parse_transaction`
helper, then broadcast `tx` / `tx.to_ef()` rather than re-parsing the original
bytes.

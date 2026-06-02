"""Serialization of BRC-24 lookup answers.

The interoperable ``output-list`` answer is a binary
``application/octet-stream`` body — the same shape py-sdk's
``LookupResolver`` reads::

    varint(n_outputs)
    for each output:
        txid           (32 bytes)
        varint(output_index)
        varint(context_length)
        context        (context_length bytes)
    <trailing BEEF section>      # currently empty; see note

Notes:
    - py-sdk 2.0.0b1's ``_parse_binary_response`` calls ``read_var_int``
      where it means ``read_var_int_num`` and so cannot decode any
      binary answer yet (an upstream bug worth filing). This module
      emits the format py-sdk *intends*, so it works once that is
      fixed; the included round-trip test decodes with the corrected
      reader to prove the bytes are well-formed.
    - The trailing BEEF section (which would let a client reconstruct
      each transaction without a second fetch) is left empty for now;
      put displayable content in each output's ``context`` instead.
      Full BEEF-backed answers wait until the layout can be verified
      against the live overlay rather than guessed.
    - The txid is written in display (big-endian) hex order. py-sdk
      currently ignores these bytes; revisit if a strict consumer cares.
"""

from __future__ import annotations

import base64
from typing import Any, Union

from bsv.utils.writer import Writer

from bsv_brc.brc24.lookup_service import OutputRef, ResolvedOutput

__all__ = [
    "serialize_output_list",
    "output_list_to_json",
    "OUTPUT_LIST_CONTENT_TYPE",
    "JSON_CONTENT_TYPE",
]

OUTPUT_LIST_CONTENT_TYPE = "application/octet-stream"
JSON_CONTENT_TYPE = "application/json"


def serialize_output_list(refs: list[OutputRef]) -> bytes:
    """Serialize lookup results to the binary BRC-24 output-list body."""
    writer = Writer()
    writer.write_var_int_num(len(refs))
    for ref in refs:
        # The txid is a fixed-width 32-byte field; a wrong length would
        # silently desync every following field in the stream. Fail loud.
        raw_txid = bytes.fromhex(ref.txid)
        if len(raw_txid) != 32:
            raise ValueError(
                f"txid must be 32 bytes (64 hex chars), got {len(raw_txid)} "
                f"for {ref.txid!r}"
            )
        if ref.output_index < 0:
            raise ValueError(f"output_index must be non-negative, got {ref.output_index}")
        writer.write(raw_txid)
        writer.write_var_int_num(ref.output_index)
        context = ref.context or b""
        writer.write_var_int_num(len(context))
        if context:
            writer.write(context)
    # Trailing BEEF section intentionally empty (see module docstring).
    return writer.to_bytes()


def output_list_to_json(
    items: list[Union[OutputRef, ResolvedOutput]]
) -> dict[str, Any]:
    """A readable, BEEF-backed JSON view of the answer.

    For non-py-sdk clients and for getting content in one round trip.
    ``beef`` (when the item is a :class:`ResolvedOutput`) and ``context``
    are base64-encoded so the bytes survive JSON. With BEEF present the
    client reconstructs the whole transaction without a second fetch.
    """
    outputs = []
    for item in items:
        entry: dict[str, Any] = {
            "txid": item.txid,
            "outputIndex": item.output_index,
            "context": base64.b64encode(item.context).decode("ascii")
            if item.context
            else None,
        }
        beef = getattr(item, "beef", None)
        if beef is not None:
            entry["beef"] = base64.b64encode(beef).decode("ascii")
        outputs.append(entry)
    return {"type": "output-list", "outputs": outputs}

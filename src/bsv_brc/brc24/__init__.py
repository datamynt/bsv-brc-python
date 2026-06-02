"""
BRC-24: Overlay Network Lookup Services (server / provider side).

The read side of an overlay node. Subclass :class:`LookupService` to
index admitted outputs and answer queries; the engine in
:mod:`bsv_brc.overlay` drives its event callbacks and serializes its
results. py-sdk ships the lookup *client* (``LookupResolver``) — this is
the *provider* interface it does not have.

Reference: https://bsv.brc.dev/overlays/0024
"""

from bsv_brc.brc24.lookup_service import LookupService, OutputRef, ResolvedOutput
from bsv_brc.brc24.wire import (
    JSON_CONTENT_TYPE,
    OUTPUT_LIST_CONTENT_TYPE,
    output_list_to_json,
    serialize_output_list,
)

__all__ = [
    "LookupService",
    "OutputRef",
    "ResolvedOutput",
    "serialize_output_list",
    "output_list_to_json",
    "OUTPUT_LIST_CONTENT_TYPE",
    "JSON_CONTENT_TYPE",
]

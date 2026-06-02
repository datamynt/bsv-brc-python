"""BRC-24 lookup service interface.

A *lookup service* is the read side of an overlay node: it is told when
outputs are admitted to a topic and when they are later spent, builds
whatever index its query model needs, and answers ``LookupQuestion``s
with a list of matching outputs. It is the piece that turns a stream of
admitted transactions into a queryable feed — for a social app, the
``ls_posts`` service that answers "give me the latest posts".

py-sdk provides the lookup *client* (``LookupResolver``); this is the
*provider* interface py-sdk does not have. The engine
(:class:`bsv_brc.overlay.OverlayEngine`) drives the event callbacks and
resolves :class:`OutputRef`s into the wire response.

Reference: https://bsv.brc.dev/overlays/0024
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Awaitable, Optional, Union

__all__ = ["OutputRef", "ResolvedOutput", "LookupService"]


@dataclass(frozen=True)
class OutputRef:
    """A reference to one admitted output, returned from a lookup.

    Args:
        txid: the transaction id (hex) holding the output.
        output_index: the output's index within that transaction.
        context: optional bytes returned alongside the outpoint — a
            handy place to put the displayable payload (e.g. a post's
            JSON) so a client gets content without a second fetch.
    """

    txid: str
    output_index: int
    context: Optional[bytes] = None


@dataclass(frozen=True)
class ResolvedOutput:
    """An :class:`OutputRef` with its BEEF resolved from storage.

    Produced by :meth:`bsv_brc.overlay.OverlayEngine.resolve` so a BEEF-
    backed answer can hand the client the whole transaction (no second
    fetch). ``beef`` is ``None`` when the engine has no stored BEEF for
    the txid (e.g. a service returned an outpoint it indexed elsewhere).
    """

    txid: str
    output_index: int
    beef: Optional[bytes] = None
    context: Optional[bytes] = None


# A lookup may return its results directly or as an awaitable.
LookupResult = Union[list[OutputRef], Awaitable[list[OutputRef]]]


class LookupService(ABC):
    """Base class for a named (``ls_*``) overlay lookup service.

    Subclass it and implement :meth:`lookup`. Override
    :meth:`output_admitted` / :meth:`output_spent` to maintain your
    index; both default to no-ops and may be sync or ``async``. A
    service receives events for *every* topic the node hosts and should
    ignore the ones its model does not care about.
    """

    @abstractmethod
    def lookup(self, question: object) -> LookupResult:
        """Answer a ``LookupQuestion`` with the matching outputs.

        ``question`` is a ``bsv.overlay_tools.LookupQuestion`` (it has
        ``.service`` and ``.query``). Return the matching outputs as a
        list of :class:`OutputRef`.
        """
        ...

    def output_admitted(
        self,
        topic: str,
        txid: str,
        output_index: int,
        locking_script: bytes,
        satoshis: int,
    ) -> Union[None, Awaitable[None]]:
        """Called when an output is admitted to ``topic``. Index it here."""
        return None

    def output_spent(
        self, topic: str, txid: str, output_index: int
    ) -> Union[None, Awaitable[None]]:
        """Called when a previously-admitted output is spent."""
        return None

    def get_documentation(self) -> str:
        return ""

    def get_metadata(self) -> dict:
        return {}

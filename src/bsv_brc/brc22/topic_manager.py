"""BRC-22 topic manager interface.

A *topic manager* decides which outputs of a submitted transaction are
admissible into its overlay topic, and which previously-admitted coins
(inputs of the new transaction) should be retained. This is the single
piece of application-specific logic BRC-22 leaves to the implementer;
:class:`bsv_brc.brc22.TopicEngine` and the ``/submit`` transport adapter
are generic and reused across every topic.

The return type is the official
``bsv.overlay_tools.ship_broadcaster.AdmittanceInstructions`` dataclass,
so a manager's output is wire-compatible with the SDK's client
(``TopicBroadcaster``/``SHIPBroadcaster``) without bsv-brc redefining
the type.

Reference: https://bsv.brc.dev/overlays/0022
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Awaitable, Union

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions

__all__ = ["TopicManager"]


class TopicManager(ABC):
    """Base class for an overlay topic's admittance logic.

    Subclass it and implement :meth:`identify_admissible_outputs`. The
    method may be written as either a regular (sync) or ``async`` method
    — :class:`bsv_brc.brc22.TopicEngine` awaits the result either way.
    """

    @abstractmethod
    def identify_admissible_outputs(
        self, beef: bytes, previous_coins: list[int]
    ) -> Union[AdmittanceInstructions, Awaitable[AdmittanceInstructions]]:
        """Return which outputs to admit and which input coins to retain.

        Args:
            beef: the full BEEF bytes of the submitted transaction — the
                same bytes the client broadcast. Parse them with
                ``bsv.transaction.Transaction.from_beef(beef)`` when you
                need the decoded transaction, inputs and outputs.
            previous_coins: indices into the transaction's *inputs* that
                are already members of this topic (i.e. this transaction
                spends coins the topic was tracking). The list is empty
                when the engine has no UTXO bookkeeping wired in (see
                ``get_previous_coins`` on :class:`TopicEngine`).

        Returns:
            An :class:`AdmittanceInstructions` with ``outputs_to_admit``
            (indices into the transaction's outputs) and
            ``coins_to_retain`` (a subset of ``previous_coins`` to keep
            tracking). May be returned directly or as an awaitable.
        """
        ...

    # --- optional spec metadata -------------------------------------
    # Overlay hosts surface these via endpoints like /listTopicManagers.
    # The defaults keep trivial managers terse.

    def get_documentation(self) -> str:
        """Human-readable Markdown describing the topic. Optional."""
        return ""

    def get_metadata(self) -> dict:
        """Structured metadata (name, description, ...). Optional."""
        return {}

"""BRC-22 topic submission engine.

The generic processing loop a Python overlay node runs when a
transaction is submitted: parse the BEEF, ask each hosted topic manager
which of the transaction's outputs are admissible, and return the
topic-keyed admittance map (the SDK's ``STEAK`` shape) the client
expects back from ``POST /submit``.

Persistence and lookup-service notification are intentionally left as
injectable callbacks so this stays a thin, storage-agnostic
orchestrator — pair it with a lookup-service layer (BRC-24, a later
release) for the read side. py-sdk supplies the client/broadcaster
side; this is the server side py-sdk does not provide.

Reference: https://bsv.brc.dev/overlays/0022
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Mapping, Optional

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF
from bsv.transaction import Transaction

from bsv_brc.brc22.topic_manager import TopicManager

__all__ = ["TopicEngine", "UnknownTopicError"]


# (topic, txid, instructions, tx) -> None | Awaitable[None]
AdmitCallback = Callable[[str, str, AdmittanceInstructions, Transaction], Any]
# (topic, tx) -> list[int] | Awaitable[list[int]]
PreviousCoinsResolver = Callable[[str, Transaction], Any]


class UnknownTopicError(ValueError):
    """Raised when a submission requests no topic this node hosts."""

    def __init__(self, requested: list[str], hosted: list[str]) -> None:
        self.requested = list(requested)
        self.hosted = list(hosted)
        # Don't echo the (attacker-controlled, unbounded) requested list
        # back; report its size and our own bounded hosted set.
        super().__init__(
            f"none of the {len(self.requested)} requested topics are hosted "
            f"by this node (hosted: {self.hosted})"
        )


async def _maybe_await(value: Any) -> Any:
    """Await ``value`` if it is awaitable, else return it unchanged.

    Lets topic managers and callbacks be written as either sync or
    ``async`` functions without the engine caring which.
    """
    if inspect.isawaitable(value):
        return await value
    return value


class TopicEngine:
    """Routes a submitted transaction to the topic managers that host it.

    Args:
        managers: mapping of ``tm_*`` topic name to its
            :class:`TopicManager`. At least one is required.
        get_previous_coins: optional callback ``(topic, tx) -> list[int]``
            returning the indices of the transaction's inputs that are
            already tracked by ``topic``. Wire this to your UTXO store to
            support coin retention/removal; omit it and managers receive
            an empty ``previous_coins`` list.
        on_admit: optional callback ``(topic, txid, instructions, tx)``
            invoked after a topic admits at least one output — the hook
            where a lookup service or storage layer indexes the new
            outputs. Sync or async.
    """

    def __init__(
        self,
        managers: Mapping[str, TopicManager],
        *,
        get_previous_coins: Optional[PreviousCoinsResolver] = None,
        on_admit: Optional[AdmitCallback] = None,
    ) -> None:
        if not managers:
            raise ValueError("TopicEngine requires at least one topic manager")
        self.managers: dict[str, TopicManager] = dict(managers)
        self._get_previous_coins = get_previous_coins
        self._on_admit = on_admit

    @property
    def hosted_topics(self) -> list[str]:
        return list(self.managers)

    async def submit(self, tagged: TaggedBEEF) -> dict[str, AdmittanceInstructions]:
        """Process a tagged BEEF submission and return the STEAK map.

        Only the requested topics this node actually hosts are
        processed; the rest are ignored (a node is under no obligation
        to handle topics it does not host). If *none* of the requested
        topics are hosted, :class:`UnknownTopicError` is raised so the
        transport can answer 400 rather than an empty 200.
        """
        requested = list(tagged.topics or [])
        hosted = [t for t in requested if t in self.managers]
        if not hosted:
            raise UnknownTopicError(requested, self.hosted_topics)

        tx = Transaction.from_beef(tagged.beef)
        txid = tx.txid()

        steak: dict[str, AdmittanceInstructions] = {}
        for topic in hosted:
            manager = self.managers[topic]
            if self._get_previous_coins is not None:
                previous_coins = await _maybe_await(
                    self._get_previous_coins(topic, tx)
                )
            else:
                previous_coins = []

            instructions = await _maybe_await(
                manager.identify_admissible_outputs(tagged.beef, previous_coins)
            )
            steak[topic] = instructions

            if self._on_admit is not None and instructions.outputs_to_admit:
                await _maybe_await(self._on_admit(topic, txid, instructions, tx))

        return steak

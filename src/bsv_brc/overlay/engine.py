"""The overlay node engine: submit + lookup, wired through storage.

:class:`OverlayEngine` is the heart of a Python overlay service host —
the piece py-sdk leaves entirely to you (it ships only the client side).
It composes:

- BRC-22 topic managers (:class:`bsv_brc.brc22.TopicManager`) that decide
  which outputs each topic admits;
- BRC-24 lookup services (:class:`bsv_brc.brc24.LookupService`) that index
  admitted outputs and answer queries;
- an :class:`bsv_brc.overlay.OverlayStorage` holding the topical UTXO set.

On ``submit`` it parses the BEEF, computes which inputs are
previously-admitted coins (so managers can retain/remove them), runs each
hosted topic manager, persists admitted outputs, and fires
``output_admitted`` / ``output_spent`` events to every lookup service. On
``lookup`` it dispatches to the named service and returns its matching
outputs.

``submit`` has the same signature as :class:`bsv_brc.brc22.TopicEngine`,
so it drops straight into the BRC-22 ``/submit`` adapter.

References:
    https://bsv.brc.dev/overlays/0022
    https://bsv.brc.dev/overlays/0024
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Mapping, Optional

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF
from bsv.transaction import Transaction

from bsv_brc.brc22.engine import UnknownTopicError
from bsv_brc.brc22.topic_manager import TopicManager
from bsv_brc.brc24.lookup_service import LookupService, OutputRef, ResolvedOutput
from bsv_brc.overlay.storage import InMemoryOverlayStorage, OverlayStorage
from bsv_brc.overlay.topic_root import outpoint_string, state_root

__all__ = ["OverlayEngine", "UnknownServiceError", "UnknownTopicError"]


class UnknownServiceError(ValueError):
    """Raised when a lookup names a service this node does not host."""

    def __init__(self, service: str, hosted: list[str]) -> None:
        self.service = service
        self.hosted = list(hosted)
        super().__init__(
            f"lookup service {service!r} is not hosted by this node "
            f"(hosted: {self.hosted})"
        )


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _norm_txid(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


class OverlayEngine:
    """A runnable overlay node: topic admittance + lookup, over storage.

    Args:
        topic_managers: ``{tm_* topic: TopicManager}``. At least one.
        lookup_services: ``{ls_* service: LookupService}``. May be empty
            (a submit-only node), but then you only need
            :class:`bsv_brc.brc22.TopicEngine`.
        storage: the topical UTXO set; defaults to an in-memory store.
    """

    def __init__(
        self,
        topic_managers: Mapping[str, TopicManager],
        lookup_services: Optional[Mapping[str, LookupService]] = None,
        *,
        storage: Optional[OverlayStorage] = None,
    ) -> None:
        if not topic_managers:
            raise ValueError("OverlayEngine requires at least one topic manager")
        self.topic_managers: dict[str, TopicManager] = dict(topic_managers)
        self.lookup_services: dict[str, LookupService] = dict(lookup_services or {})
        self.storage: OverlayStorage = storage or InMemoryOverlayStorage()
        # Serializes the check-then-act in submit() so concurrent
        # submissions cannot both classify the same coin as live and
        # double-admit/double-spend it — necessary because an async
        # TopicManager yields the event loop mid-critical-section.
        self._submit_lock = asyncio.Lock()

    @property
    def hosted_topics(self) -> list[str]:
        return list(self.topic_managers)

    @property
    def hosted_services(self) -> list[str]:
        return list(self.lookup_services)

    async def submit(
        self, tagged: TaggedBEEF
    ) -> dict[str, AdmittanceInstructions]:
        """Process a submission: admit outputs, track spends, fire events."""
        requested = list(tagged.topics or [])
        hosted = [t for t in requested if t in self.topic_managers]
        if not hosted:
            raise UnknownTopicError(requested, self.hosted_topics)

        tx = Transaction.from_beef(tagged.beef)
        txid = tx.txid()

        # The whole check-then-act (read previous coins -> ask manager ->
        # write admits/spends -> notify services) must be atomic across
        # the awaited manager/service calls, or two concurrent submits
        # spending the same coin both see it live and double-process it.
        async with self._submit_lock:
            steak: dict[str, AdmittanceInstructions] = {}
            admitted: list[tuple[str, str, int, bytes, int]] = []
            spent: list[tuple[str, str, int]] = []

            for topic in hosted:
                manager = self.topic_managers[topic]

                previous_coins: list[int] = []
                input_map: dict[int, tuple[str, int]] = {}
                for i, inp in enumerate(tx.inputs):
                    ptxid = _norm_txid(getattr(inp, "source_txid", None))
                    pidx = getattr(inp, "source_output_index", None)
                    if (
                        ptxid is not None
                        and pidx is not None
                        and self.storage.is_unspent(topic, ptxid, pidx)
                    ):
                        previous_coins.append(i)
                        input_map[i] = (ptxid, pidx)

                instructions = await _maybe_await(
                    manager.identify_admissible_outputs(tagged.beef, previous_coins)
                )
                steak[topic] = instructions

                if instructions.outputs_to_admit:
                    self.storage.put_beef(txid, tagged.beef)

                for oi in instructions.outputs_to_admit:
                    out = tx.outputs[oi]
                    script = bytes.fromhex(out.locking_script.hex())
                    satoshis = int(getattr(out, "satoshis", 0) or 0)
                    self.storage.insert_output(topic, txid, oi, script, satoshis)
                    admitted.append((topic, txid, oi, script, satoshis))

                # Every input that resolved to a *live* topical coin is
                # consumed on-chain by this transaction, so it is spent —
                # regardless of coins_to_retain. Retention/removal is a
                # history concern (keep vs delete the spent record), not
                # liveness; a retention preference cannot un-spend a coin
                # the chain already consumed. We never leave a spent coin
                # live. (Modeling retained-for-history in storage is a
                # future refinement; see CHANGELOG.)
                for ii in input_map:
                    ptxid, pidx = input_map[ii]
                    self.storage.mark_spent(topic, ptxid, pidx)
                    spent.append((topic, ptxid, pidx))

            # Notify every lookup service; each filters by topic in its
            # own callbacks (a service may ignore topics outside its
            # model).
            for service in self.lookup_services.values():
                for topic, t, oi, script, satoshis in admitted:
                    await _maybe_await(
                        service.output_admitted(topic, t, oi, script, satoshis)
                    )
                for topic, t, oi in spent:
                    await _maybe_await(service.output_spent(topic, t, oi))

            return steak

    async def lookup(self, question: Any) -> list[OutputRef]:
        """Dispatch a ``LookupQuestion`` to its named service."""
        service_name = getattr(question, "service", None)
        service = self.lookup_services.get(service_name)
        if service is None:
            raise UnknownServiceError(service_name, self.hosted_services)
        refs = await _maybe_await(service.lookup(question))
        return list(refs or [])

    def resolve(self, refs: list[OutputRef]) -> list[ResolvedOutput]:
        """Attach each output's stored BEEF, for a BEEF-backed answer.

        Lets the client reconstruct the whole transaction in one round
        trip. ``beef`` is ``None`` when the engine has no BEEF stored for
        that txid.
        """
        return [
            ResolvedOutput(
                txid=ref.txid,
                output_index=ref.output_index,
                beef=self.storage.get_beef(ref.txid),
                context=ref.context,
            )
            for ref in refs
        ]

    def topic_root(self, topic: str) -> str:
        """Per-topic state root over ``topic``'s live (unspent) outputs.

        Returns the canonical lowercase-hex SHA-256 state root defined by
        the peck-social-overlay spec (see
        :mod:`bsv_brc.overlay.topic_root`). It matches the ``stateRoot``
        that ``overlay.peck.to`` publishes at ``GET /state`` for the same
        live UTXO set — a cross-implementation interoperable commitment.
        An empty topic yields
        :data:`bsv_brc.overlay.topic_root.EMPTY_STATE_ROOT`.
        """
        return self.topic_state(topic)["stateRoot"]

    def topic_state(self, topic: str) -> dict[str, object]:
        """``{"count": n, "stateRoot": hex}`` for one hosted topic.

        ``count`` is the number of distinct live outpoints the root
        commits to. Same shape (per topic) as ``overlay.peck.to``'s
        ``GET /state`` entries.
        """
        if topic not in self.topic_managers:
            raise UnknownTopicError([topic], self.hosted_topics)
        outpoints = sorted(
            {
                outpoint_string(o.txid, o.output_index)
                for o in self.storage.outputs(topic)
                if not o.spent
            }
        )
        return {"count": len(outpoints), "stateRoot": state_root(outpoints)}

    def topic_roots(self) -> dict[str, str]:
        """``{topic: state_root}`` for every hosted topic."""
        return {t: self.topic_root(t) for t in self.hosted_topics}

    def topic_states(self) -> list[dict[str, object]]:
        """``[{"topic", "count", "stateRoot"}, ...]`` for all hosted topics.

        The body a ``/state`` endpoint serves — matches the per-topic
        shape ``overlay.peck.to`` publishes.
        """
        return [
            {"topic": t, **self.topic_state(t)} for t in self.hosted_topics
        ]

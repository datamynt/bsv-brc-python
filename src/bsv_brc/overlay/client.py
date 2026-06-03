"""
Overlay CLIENT — the consumer side of an overlay node.

py-sdk ships ``LookupResolver`` / ``TopicBroadcaster``, but in practice
every Python service in the ecosystem hand-rolls its own httpx + header
+ STEAK/JSON-shape guessing against ``overlay.peck.to`` — and the
details are easy to get wrong (the ``x-topics`` header is a JSON array,
``@bsv/overlay`` returns ``200`` with an empty ``outputsToAdmit`` to mean
*rejected*, lookup answers come back as a BEEF-bearing output-list).
This module captures the wire contract once.

Two layers, matching the rest of bsv-brc:
- Pure, I/O-free builders/parsers (``build_submit_headers``,
  ``parse_steak``, ``parse_lookup_answer``, ``parse_state``) that an
  async app can wire into its own httpx/aiohttp.
- A batteries-included synchronous :class:`OverlayClient` (stdlib
  ``urllib`` only, no new deps) that defaults to ``overlay.peck.to`` so
  an app can read/submit in a couple of lines, and can verify a topic's
  published state root against its own :func:`state_root`.

Wire contract (verified against overlay.peck.to / @bsv/overlay):
- submit:  POST {host}/submit, Content-Type application/octet-stream,
           header ``x-topics: ["tm_..."]`` (JSON array), body = BEEF.
           Response = STEAK JSON ``{topic: {outputsToAdmit, coinsToRetain}}``.
           NO admission = HTTP 200 with every outputsToAdmit empty.
- lookup:  POST {host}/lookup JSON ``{service, query}`` with
           ``Accept: application/json``. Response =
           ``{type: "output-list", outputs: [{beef, outputIndex, ...}]}``
           where ``beef`` is a byte array (overlay.peck.to) or base64
           (a bsv-brc node).
- state:   GET {host}/state -> ``{topics: [{topic, count, stateRoot}]}``.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions

from bsv_brc.overlay.topic_root import state_root

__all__ = [
    "DEFAULT_OVERLAY_HOST",
    "OverlayClient",
    "SubmitResult",
    "LookupOutput",
    "NoAdmissionError",
    "OverlayHTTPError",
    "build_submit_headers",
    "parse_steak",
    "parse_lookup_answer",
    "parse_state",
]

DEFAULT_OVERLAY_HOST = "https://overlay.peck.to"


class OverlayHTTPError(RuntimeError):
    """A non-2xx response from an overlay node."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"overlay returned HTTP {status}: {body[:200]}")


class NoAdmissionError(RuntimeError):
    """A submission was accepted (HTTP 200) but admitted no outputs."""

    def __init__(self, topics: list[str]) -> None:
        self.topics = topics
        super().__init__(
            f"overlay admitted no outputs for topics {topics} "
            f"(200 with empty outputsToAdmit = topic validation rejected)"
        )


@dataclass
class SubmitResult:
    """Parsed STEAK from a ``/submit``."""

    steak: dict[str, AdmittanceInstructions]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def admitted(self) -> bool:
        """True if any topic admitted at least one output."""
        return any(ai.outputs_to_admit for ai in self.steak.values())


@dataclass(frozen=True)
class LookupOutput:
    """One output from a lookup answer."""

    output_index: int
    beef: bytes
    txid: Optional[str] = None
    context: Optional[bytes] = None


# --- pure builders / parsers (no I/O) ------------------------------------


def build_submit_headers(topics: list[str]) -> dict[str, str]:
    """Headers for a ``/submit`` — ``x-topics`` is a JSON array."""
    return {
        "Content-Type": "application/octet-stream",
        "X-Topics": json.dumps(topics),
    }


def parse_steak(obj: dict[str, Any]) -> dict[str, AdmittanceInstructions]:
    """Parse a STEAK JSON map into ``{topic: AdmittanceInstructions}``."""
    steak: dict[str, AdmittanceInstructions] = {}
    for topic, instr in (obj or {}).items():
        if not isinstance(instr, dict):
            continue
        steak[topic] = AdmittanceInstructions(
            outputs_to_admit=list(instr.get("outputsToAdmit") or []),
            coins_to_retain=list(instr.get("coinsToRetain") or []),
            coins_removed=(
                list(instr["coinsRemoved"])
                if instr.get("coinsRemoved") is not None
                else None
            ),
        )
    return steak


def _coerce_beef(value: Any) -> bytes:
    """A lookup answer's ``beef`` is a byte array or a base64 string."""
    if isinstance(value, list):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return b""


def _txid_from_atomic_beef(beef: bytes) -> Optional[str]:
    """Extract the subject txid from an AtomicBEEF (BRC-95) prefix.

    AtomicBEEF = 0x01010101 || 32-byte subject txid (LE) || BEEF. We read
    the txid straight from the header so we needn't parse the BEEF (which
    may be V2, unsupported by some bsv-sdk versions). Returns None when
    the bytes are not AtomicBEEF.
    """
    if len(beef) >= 36 and beef[:4] == b"\x01\x01\x01\x01":
        return beef[4:36][::-1].hex()
    return None


def parse_lookup_answer(obj: dict[str, Any]) -> list[LookupOutput]:
    """Parse a JSON ``output-list`` answer into :class:`LookupOutput`s."""
    outputs: list[LookupOutput] = []
    for o in (obj or {}).get("outputs") or []:
        beef = _coerce_beef(o.get("beef"))
        context = o.get("context")
        ctx_bytes = _coerce_beef(context) if context is not None else None
        txid = o.get("txid") or _txid_from_atomic_beef(beef)
        outputs.append(
            LookupOutput(
                output_index=int(o.get("outputIndex", 0)),
                beef=beef,
                txid=txid,
                context=ctx_bytes or None,
            )
        )
    return outputs


def parse_state(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ``topics`` list from a ``/state`` response."""
    return list((obj or {}).get("topics") or [])


# --- batteries-included sync client --------------------------------------

# fetch(method, url, headers, body) -> (status_code, response_bytes)
Fetch = Callable[[str, str, dict, Optional[bytes]], tuple]


def _urllib_fetch(
    method: str, url: str, headers: dict, body: Optional[bytes]
) -> tuple:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_urllib_fetch.timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as exc:  # noqa: PERF203
        return exc.code, exc.read()


_urllib_fetch.timeout = 20  # type: ignore[attr-defined]


class OverlayClient:
    """A small synchronous overlay consumer (submit / lookup / state).

    Defaults to ``overlay.peck.to`` so an app gets a working overlay
    connection with no config, and is fully swappable to a self-hosted
    node. Uses stdlib ``urllib`` (no new dependencies); async apps can
    instead use the pure ``parse_*`` helpers with their own HTTP client,
    or pass a custom ``fetch``.

    Args:
        host: overlay base URL (no trailing slash needed).
        timeout: per-request timeout in seconds.
        fetch: optional ``(method, url, headers, body) -> (status, bytes)``
            transport override (e.g. to plug in httpx or for testing).
    """

    def __init__(
        self,
        host: str = DEFAULT_OVERLAY_HOST,
        *,
        timeout: int = 20,
        fetch: Optional[Fetch] = None,
    ) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout
        self._fetch = fetch or _urllib_fetch

    def _request(
        self, method: str, path: str, headers: dict, body: Optional[bytes]
    ) -> bytes:
        if self._fetch is _urllib_fetch:
            _urllib_fetch.timeout = self.timeout  # type: ignore[attr-defined]
        status, data = self._fetch(method, f"{self.host}{path}", headers, body)
        if not (200 <= status < 300):
            raise OverlayHTTPError(status, data.decode("utf-8", "replace"))
        return data

    def submit(
        self, beef: bytes, topics: list[str], *, require_admission: bool = False
    ) -> SubmitResult:
        """Submit a BEEF to ``topics`` and parse the STEAK response.

        With ``require_admission=True`` a 200-but-empty admission raises
        :class:`NoAdmissionError` (the silent-rejection trap), so callers
        that must not lose data can fail loud.
        """
        data = self._request(
            "POST", "/submit", build_submit_headers(topics), beef
        )
        obj = json.loads(data or b"{}")
        result = SubmitResult(steak=parse_steak(obj), raw=obj)
        if require_admission and not result.admitted:
            raise NoAdmissionError(topics)
        return result

    def lookup(
        self, service: str, query: Optional[dict] = None
    ) -> list[LookupOutput]:
        """Query a lookup service and parse the output-list answer."""
        body = json.dumps({"service": service, "query": query or {}}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        data = self._request("POST", "/lookup", headers, body)
        return parse_lookup_answer(json.loads(data or b"{}"))

    def state(self) -> list[dict[str, Any]]:
        """Fetch ``GET /state`` and return the per-topic state list."""
        data = self._request("GET", "/state", {"Accept": "application/json"}, None)
        return parse_state(json.loads(data or b"{}"))

    def topic_state(self, topic: str) -> Optional[dict[str, Any]]:
        """The ``/state`` entry for one topic, or None if not hosted."""
        for entry in self.state():
            if entry.get("topic") == topic:
                return entry
        return None

    def verify_state(self, topic: str, outpoints: list[str]) -> bool:
        """Check our local state root over ``outpoints`` matches the node's.

        ``outpoints`` are ``"<txid>:<vout>"`` strings. Recomputes the
        canonical :func:`state_root` and compares it to the node's
        published ``stateRoot`` for ``topic`` — a cheap integrity check
        that our view of a topic's live set agrees with the overlay's.
        """
        entry = self.topic_state(topic)
        if entry is None:
            return False
        return state_root(outpoints) == entry.get("stateRoot")

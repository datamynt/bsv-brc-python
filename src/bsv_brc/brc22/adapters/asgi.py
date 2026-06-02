"""ASGI adapter exposing a BRC-22 ``/submit`` endpoint.

Mount this in front of (or alongside) any ASGI app — Starlette,
FastAPI, FastHTML, Litestar, Quart — to let clients broadcast
transactions to the topics this node hosts. It mirrors the adapter
style of :mod:`bsv_brc.brc104.adapters.asgi`: a framework-agnostic ASGI
callable plus small, importable parse/serialize helpers.

Wire format (BRC-22)::

    POST <mount path>
    Content-Type: application/octet-stream
    X-Topics: ["tm_example", ...]              (JSON array, required)
    X-Includes-Off-Chain-Values: true          (optional)

    body = BEEF bytes
        or, when off-chain values are included:
           varint(len(beef)) || beef || off_chain_values

Response — ``200 application/json``, the topic-keyed STEAK map::

    {
      "tm_example": {
        "outputsToAdmit": [0, 2],
        "coinsToRetain": [],
        "coinsRemoved": []
      }
    }

The endpoint only inspects the request *method* (it answers ``POST``
and rejects everything else with 405), so you choose the path by where
you mount it — typically ``/submit``.

Usage (Starlette/FastAPI)::

    from starlette.applications import Starlette
    from starlette.routing import Mount
    from bsv_brc.brc22 import TopicEngine
    from bsv_brc.brc22.adapters.asgi import SubmitASGIApp

    engine = TopicEngine({"tm_example": MyTopicManager()})
    app = Starlette(routes=[Mount("/submit", app=SubmitASGIApp(engine))])
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF

from bsv_brc._asgi import (
    MAX_BODY_BYTES,
    BodyTooLarge,
    content_length_exceeds,
    read_body_capped,
)
from bsv_brc.brc22.engine import TopicEngine, UnknownTopicError

logger = logging.getLogger(__name__)

__all__ = [
    "SubmitASGIApp",
    "make_submit_route",
    "process_submit",
    "instructions_to_dict",
    "steak_to_dict",
    "parse_submit_body",
    "parse_topics_header",
    "TOPICS_HEADER",
    "OFF_CHAIN_HEADER",
    "MAX_TOPICS",
]

TOPICS_HEADER = "x-topics"
OFF_CHAIN_HEADER = "x-includes-off-chain-values"
# Cap the topic count so a giant X-Topics header can't drive unbounded work.
MAX_TOPICS = 64


def parse_topics_header(raw: str) -> Optional[list[str]]:
    """Parse an ``X-Topics`` header into a list of topic names.

    Accepts both wire formats: the canonical py-sdk one, a bare
    comma-separated string (``TopicBroadcaster`` sends
    ``",".join(topics)``), and a JSON array (``["tm_a", "tm_b"]``).
    Returns the parsed list, or ``None`` if the value is unparseable.
    """
    raw = raw.strip()
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, list) or not all(
            isinstance(t, str) for t in parsed
        ):
            return None
        return [t.strip() for t in parsed if t.strip()]
    # Canonical py-sdk format: comma-separated.
    return [t.strip() for t in raw.split(",") if t.strip()]


def instructions_to_dict(ai: AdmittanceInstructions) -> dict[str, list[int]]:
    """Serialize AdmittanceInstructions to the camelCase BRC-22 JSON shape."""
    out: dict[str, list[int]] = {
        "outputsToAdmit": list(ai.outputs_to_admit),
        "coinsToRetain": list(ai.coins_to_retain),
    }
    if ai.coins_removed is not None:
        out["coinsRemoved"] = list(ai.coins_removed)
    return out


def steak_to_dict(
    steak: dict[str, AdmittanceInstructions]
) -> dict[str, dict[str, list[int]]]:
    """Serialize a STEAK map to JSON-ready camelCase dicts."""
    return {topic: instructions_to_dict(ai) for topic, ai in steak.items()}


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a Bitcoin VarInt at ``offset``; return (value, next_offset)."""
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), offset + 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), offset + 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), offset + 9


def parse_submit_body(
    body: bytes, *, includes_off_chain: bool
) -> tuple[bytes, Optional[bytes]]:
    """Split a /submit body into (beef, off_chain_values).

    When ``includes_off_chain`` is false the whole body is the BEEF.
    Otherwise the body is ``varint(len(beef)) || beef || off_chain``.
    """
    if not includes_off_chain:
        return body, None
    if not body:
        raise ValueError("empty body with off-chain framing")
    length, start = _read_varint(body, 0)
    end = start + length
    if end > len(body):
        raise ValueError("declared BEEF length exceeds body")
    return body[start:end], body[end:] or None


def _is_truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


def _scope_headers(scope: dict) -> dict[str, str]:
    return {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in scope.get("headers", [])
    }


async def _send_json(
    send: Callable[[dict], Awaitable[None]], status: int, payload: Any
) -> None:
    body = json.dumps(payload, default=str).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def process_submit(
    *,
    method: str,
    headers: dict[str, str],
    body: bytes,
    engine: TopicEngine,
) -> tuple[int, Any]:
    """Run a BRC-22 submission, framework-free.

    Validates the method, the ``X-Topics`` header and the (optionally
    off-chain-framed) BEEF body, runs the engine, and returns a
    ``(status_code, json_payload)`` pair. Shared by the raw ASGI app
    and the Starlette route helper so both behave identically.

    ``headers`` keys must be lowercased.
    """
    if method.upper() != "POST":
        return 405, {"error": "method not allowed; use POST"}

    topics_raw = headers.get(TOPICS_HEADER)
    if not topics_raw:
        return 400, {"error": f"missing required {TOPICS_HEADER} header"}
    topics = parse_topics_header(topics_raw)
    if topics is None:
        return 400, {"error": f"invalid {TOPICS_HEADER} header"}
    if not topics:
        return 400, {"error": f"empty {TOPICS_HEADER} header"}
    if len(topics) > MAX_TOPICS:
        return 400, {"error": f"too many topics in {TOPICS_HEADER} (max {MAX_TOPICS})"}

    try:
        beef, off_chain = parse_submit_body(
            body, includes_off_chain=_is_truthy(headers.get(OFF_CHAIN_HEADER))
        )
    except (ValueError, IndexError) as exc:
        return 400, {"error": f"malformed body: {exc}"}

    tagged = TaggedBEEF(beef=beef, topics=topics, off_chain_values=off_chain)

    try:
        steak = await engine.submit(tagged)
    except UnknownTopicError as exc:
        return 400, {"error": str(exc)}
    except Exception:  # malformed BEEF, manager error, ...
        # Don't reflect internal exception text to the client (it may
        # carry DB DSNs, file paths, etc. from a user TopicManager).
        logger.exception("BRC-22 submit failed")
        return 400, {"error": "submission failed"}

    return 200, steak_to_dict(steak)


class SubmitASGIApp:
    """A mountable ASGI app implementing the BRC-22 ``/submit`` endpoint.

    Useful for any ASGI server. Note that mounting it in Starlette via
    ``Mount("/submit", app=...)`` triggers a trailing-slash redirect for
    ``POST /submit``; prefer :func:`make_submit_route` in Starlette/
    FastAPI to avoid that. Args:
        engine: the :class:`TopicEngine` that holds this node's topic
            managers and runs the admittance loop.
    """

    def __init__(
        self, engine: TopicEngine, *, max_body_bytes: int = MAX_BODY_BYTES
    ) -> None:
        if engine is None:
            raise ValueError("SubmitASGIApp requires a TopicEngine")
        self.engine = engine
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await _send_json(send, 400, {"error": "http requests only"})
            return

        try:
            body = await read_body_capped(receive, self.max_body_bytes)
        except BodyTooLarge as exc:
            await _send_json(send, 413, {"error": str(exc)})
            return
        status, payload = await process_submit(
            method=scope.get("method", ""),
            headers=_scope_headers(scope),
            body=body,
            engine=self.engine,
        )
        await _send_json(send, status, payload)


def make_submit_route(
    engine: TopicEngine, path: str = "/submit", *, max_body_bytes: int = MAX_BODY_BYTES
) -> Any:
    """Build a Starlette ``Route`` for the BRC-22 ``/submit`` endpoint.

    Unlike mounting :class:`SubmitASGIApp`, a Route matches the exact
    path with no trailing-slash redirect — so clients can ``POST`` to
    ``/submit`` directly. Works with both Starlette and FastAPI.

    Requires the ``starlette`` extra::

        from bsv_brc.brc22 import TopicEngine
        from bsv_brc.brc22.adapters.asgi import make_submit_route

        engine = TopicEngine({"tm_example": MyManager()})
        app = Starlette(routes=[make_submit_route(engine)])
    """
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def _endpoint(request: "Request") -> "JSONResponse":
        if content_length_exceeds(
            request.headers.get("content-length"), max_body_bytes
        ):
            return JSONResponse({"error": "request body too large"}, status_code=413)
        body = await request.body()
        headers = {k.lower(): v for k, v in request.headers.items()}
        status, payload = await process_submit(
            method=request.method,
            headers=headers,
            body=body,
            engine=engine,
        )
        return JSONResponse(payload, status_code=status)

    return Route(path, _endpoint, methods=["POST"])

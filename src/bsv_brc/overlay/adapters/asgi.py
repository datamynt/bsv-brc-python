"""ASGI adapter for the overlay node: ``/lookup`` and a full app factory.

Pairs with :mod:`bsv_brc.brc22.adapters.asgi` (which provides ``/submit``)
to expose a complete overlay node. :func:`create_overlay_app` wires both
endpoints around an :class:`bsv_brc.overlay.OverlayEngine` in a few lines.

``/lookup`` accepts ``POST {"service": "...", "query": ...}`` (JSON) and
returns the binary BRC-24 output-list body py-sdk's ``LookupResolver``
reads (``application/octet-stream``). See :mod:`bsv_brc.brc24.wire`.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Optional

import asyncio
import logging

from bsv.overlay_tools.lookup_resolver import LookupQuestion

from bsv_brc._asgi import (
    MAX_BODY_BYTES,
    BodyTooLarge,
    content_length_exceeds,
    read_body_capped,
)
from bsv_brc.brc24.wire import (
    JSON_CONTENT_TYPE,
    OUTPUT_LIST_CONTENT_TYPE,
    output_list_to_json,
    serialize_output_list,
)
from bsv_brc.overlay.engine import OverlayEngine, UnknownServiceError

logger = logging.getLogger(__name__)

__all__ = [
    "LookupASGIApp",
    "make_lookup_route",
    "make_state_route",
    "create_overlay_app",
    "process_lookup",
]


def _wants_json(accept: str) -> bool:
    """A client opts into the BEEF-backed JSON answer via Accept."""
    return "application/json" in (accept or "").lower()


async def process_lookup(
    *, method: str, body: bytes, engine: OverlayEngine, accept: str = ""
) -> tuple[int, str, bytes]:
    """Run a lookup, framework-free. Returns (status, content_type, body).

    Default answer is the binary BRC-24 output-list (py-sdk compatible).
    A client that sends ``Accept: application/json`` gets the BEEF-backed
    JSON answer instead, so it reconstructs each transaction without a
    second fetch.
    """
    if method.upper() != "POST":
        return 405, JSON_CONTENT_TYPE, _json({"error": "method not allowed; use POST"})

    try:
        payload = json.loads(body or b"{}")
        service = payload["service"]
    except (json.JSONDecodeError, TypeError):
        return 400, JSON_CONTENT_TYPE, _json({"error": "body must be JSON"})
    except KeyError:
        return 400, JSON_CONTENT_TYPE, _json({"error": "missing 'service'"})

    question = LookupQuestion(service=service, query=payload.get("query"))
    try:
        refs = await engine.lookup(question)
    except UnknownServiceError as exc:
        return 400, JSON_CONTENT_TYPE, _json({"error": str(exc)})
    except Exception:  # service error
        # Don't reflect internal exception text (it may carry a user
        # LookupService's DB/file/secret details) to the client.
        logger.exception("BRC-24 lookup failed")
        return 400, JSON_CONTENT_TYPE, _json({"error": "lookup failed"})

    if _wants_json(accept):
        # resolve() does one storage read per ref; offload so a large
        # BEEF-backed answer over SQLite does not block the event loop.
        resolved = await asyncio.to_thread(engine.resolve, refs)
        return 200, JSON_CONTENT_TYPE, _json(output_list_to_json(resolved))
    return 200, OUTPUT_LIST_CONTENT_TYPE, serialize_output_list(refs)


def _json(obj: Any) -> bytes:
    return json.dumps(obj, default=str).encode("utf-8")


class LookupASGIApp:
    """A mountable raw-ASGI app implementing ``/lookup``.

    Prefer :func:`make_lookup_route` under Starlette/FastAPI to avoid the
    trailing-slash redirect a ``Mount`` adds to ``POST`` requests.
    """

    def __init__(
        self, engine: OverlayEngine, *, max_body_bytes: int = MAX_BODY_BYTES
    ) -> None:
        if engine is None:
            raise ValueError("LookupASGIApp requires an OverlayEngine")
        self.engine = engine
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await _send(send, 400, "application/json", _json({"error": "http only"}))
            return
        try:
            body = await read_body_capped(receive, self.max_body_bytes)
        except BodyTooLarge as exc:
            await _send(send, 413, "application/json", _json({"error": str(exc)}))
            return
        accept = ""
        for k, v in scope.get("headers", []):
            if k.lower() == b"accept":
                accept = v.decode("latin-1")
                break
        status, ctype, payload = await process_lookup(
            method=scope.get("method", ""),
            body=body,
            engine=self.engine,
            accept=accept,
        )
        await _send(send, status, ctype, payload)


async def _send(send: Any, status: int, content_type: str, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode("ascii")),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def make_lookup_route(
    engine: OverlayEngine, path: str = "/lookup", *, max_body_bytes: int = MAX_BODY_BYTES
) -> Any:
    """Build a Starlette ``Route`` for ``/lookup`` (no redirect)."""
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    async def _endpoint(request: "Request") -> "Response":
        if content_length_exceeds(
            request.headers.get("content-length"), max_body_bytes
        ):
            return Response(
                _json({"error": "request body too large"}),
                status_code=413,
                media_type=JSON_CONTENT_TYPE,
            )
        body = await request.body()
        status, ctype, payload = await process_lookup(
            method=request.method,
            body=body,
            engine=engine,
            accept=request.headers.get("accept", ""),
        )
        return Response(payload, status_code=status, media_type=ctype)

    return Route(path, _endpoint, methods=["POST"])


def make_state_route(engine: OverlayEngine, path: str = "/state") -> Any:
    """Build a Starlette ``Route`` serving the topic state-root overview.

    ``GET /state`` returns ``{"status": "ok", "topics": [{"topic",
    "count", "stateRoot"}, ...]}`` — the same verifiable contract
    ``overlay.peck.to`` exposes, with state roots that match it for the
    same live UTXO set.
    """
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def _endpoint(_request: "Request") -> "JSONResponse":
        return JSONResponse({"status": "ok", "topics": engine.topic_states()})

    return Route(path, _endpoint, methods=["GET"])


def create_overlay_app(
    engine: OverlayEngine,
    *,
    submit_path: str = "/submit",
    lookup_path: str = "/lookup",
    state_path: str = "/state",
    extra_routes: Optional[list] = None,
) -> Any:
    """Build a Starlette app exposing ``/submit`` + ``/lookup`` + ``/state``.

    ``GET /state`` publishes per-topic state roots in the same shape
    ``overlay.peck.to`` uses. Requires the ``starlette`` extra. Compose
    further by wrapping the
    result with :func:`bsv_brc.build_brc_app` for auth + payments, or by
    passing ``extra_routes`` for app-specific endpoints (a feed view,
    etc.).
    """
    from starlette.applications import Starlette

    from bsv_brc.brc22.adapters.asgi import make_submit_route

    routes = [
        make_submit_route(engine, submit_path),
        make_lookup_route(engine, lookup_path),
        make_state_route(engine, state_path),
    ]
    if extra_routes:
        routes.extend(extra_routes)
    return Starlette(routes=routes)

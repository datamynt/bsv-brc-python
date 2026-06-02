"""Shared ASGI helpers for the overlay endpoints.

Kept tiny and dependency-free so both the BRC-22 ``/submit`` and the
overlay ``/lookup`` adapters share one capped body reader rather than
each rolling their own unbounded loop.
"""

from __future__ import annotations

from typing import Awaitable, Callable

__all__ = ["MAX_BODY_BYTES", "BodyTooLarge", "read_body_capped", "content_length_exceeds"]

# Default cap on a request body. BEEF with ancestry can be sizeable, so
# this is generous; override per-endpoint where needed. The point is to
# refuse an unbounded stream that would OOM the worker.
MAX_BODY_BYTES = 32 * 1024 * 1024  # 32 MiB


class BodyTooLarge(Exception):
    """Raised when a request body exceeds the configured cap."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        super().__init__(f"request body exceeds {max_bytes} bytes")


async def read_body_capped(
    receive: Callable[[], Awaitable[dict]], max_bytes: int = MAX_BODY_BYTES
) -> bytes:
    """Read an ASGI request body, aborting if it exceeds ``max_bytes``.

    Accumulates into a list and joins once (avoids the ~2x reallocation
    of repeated ``bytes +=``).
    """
    chunks: list[bytes] = []
    total = 0
    more_body = True
    while more_body:
        message = await receive()
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > max_bytes:
            raise BodyTooLarge(max_bytes)
        chunks.append(chunk)
        more_body = message.get("more_body", False)
    return b"".join(chunks)


def content_length_exceeds(content_length: str | None, max_bytes: int) -> bool:
    """True if a Content-Length header is present and over the cap.

    A cheap early rejection for framework paths (e.g. Starlette
    ``request.body()``) that buffer before we can intercept; chunked
    requests without a length still rely on the server's own limit.
    """
    if not content_length:
        return False
    try:
        return int(content_length) > max_bytes
    except ValueError:
        return False

"""
ASGI adapter for BRC-138 single-use signed proofs (Starlette/FastAPI/FastHTML).

The BRC-138 spec deliberately leaves transport open; this adapter provides a
convenient default: a proof is read from the request — either the
``x-bsv-auth-proof`` header (the wire JSON) or a ``proof`` member of a JSON
body — verified, and on success the authenticated identity key is exposed to
the wrapped application as ``scope["bsv_auth_proof"]`` (and
``scope["state"]["bsv_auth_proof"]`` so ``request.state.auth_proof`` works in
Starlette). On failure a 401 JSON response is returned and the wrapped
application is never invoked.

Because the middleware may consume the request body to find the proof, the
body is buffered and replayed to the wrapped application unchanged (the same
pattern as :class:`bsv_brc.brc104.adapters.asgi.AuthMiddleware`).
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from bsv_brc._asgi import MAX_BODY_BYTES, BodyTooLarge, read_body_capped
from bsv_brc.brc138.proof import (
    DEFAULT_PROTOCOL,
    AuthProof,
    AuthProofError,
    verify_auth_proof,
)

PROOF_HEADER = "x-bsv-auth-proof"

ASGIApp = Callable[
    [dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]],
    Awaitable[None],
]

# Type for the proof-extraction callback: given the raw request bytes and the
# request headers, return the proof wire dict or None.
GetProofFn = Callable[[bytes, list[tuple[bytes, bytes]]], dict[str, Any] | None]


async def _send_json(
    send: Callable[[dict], Awaitable[None]], status: int, payload: dict
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


def _header_value(headers: list[tuple[bytes, bytes]], name: str) -> str | None:
    target = name.lower().encode("latin-1")
    for k, v in headers:
        if k.lower() == target:
            return v.decode("latin-1")
    return None


def get_proof_from_header_or_body(
    body: bytes,
    headers: list[tuple[bytes, bytes]],
) -> dict[str, Any] | None:
    """Default proof extraction: header first, else a ``proof`` JSON member."""
    header = _header_value(headers, PROOF_HEADER)
    if header:
        parsed = json.loads(header)
        return parsed if isinstance(parsed, dict) else None
    if not body:
        return None
    data = json.loads(body.decode("utf-8"))
    proof = data.get("proof") if isinstance(data, dict) else None
    return proof if isinstance(proof, dict) else None


def _wallet_identity_key(wallet: Any) -> bytes | str:
    """Best-effort extraction of a wallet's identity private key."""
    for method in ("get_private_key", "get_identity_key"):
        fn = getattr(wallet, method, None)
        if fn is None:
            continue
        try:
            value = fn("identity") if method == "get_private_key" else fn()
        except TypeError:
            value = fn()
        if value is not None:
            return value
    raise AuthProofError(
        "cannot read identity private key from wallet; pass get_identity_private_key"
    )


class AuthProofMiddleware:
    """
    Raw-ASGI middleware that authenticates requests with a BRC-138 proof.

    Args:
        app: The wrapped ASGI application.
        wallet: The server wallet whose identity key clients sign toward. Used
            only to read the server's identity private key (see
            ``get_identity_private_key``).
        expected_action: The only action this deployment authorizes, e.g.
            ``"login"``.
        get_identity_private_key: Callable returning the server's identity
            private key (32 bytes or hex). Defaults to a best-effort read of
            ``wallet.get_private_key("identity")``.
        get_proof: Optional ``(body, headers) -> dict | None`` callback.
            Defaults to :func:`get_proof_from_header_or_body`.
        single_use_store: Optional
            :class:`~bsv_brc.brc138.store.SingleUseStore`. Pass one in
            production; without it replay protection is disabled.
        protocol / validity_window_ms / clock_skew_ms: Verification parameters;
            must match the client's.
        excluded_paths: Paths that skip authentication (e.g. the BRC-103
            handshake endpoint).
        max_body_bytes: Cap on the buffered request body.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        wallet: Any,
        expected_action: str,
        get_identity_private_key: Callable[[], bytes | str] | None = None,
        get_proof: GetProofFn | None = None,
        single_use_store: Any = None,
        protocol: Any = DEFAULT_PROTOCOL,
        validity_window_ms: int = 120_000,
        clock_skew_ms: int = 30_000,
        excluded_paths: set[str] | None = None,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        if wallet is None:
            raise ValueError("AuthProofMiddleware requires a wallet instance")
        self.app = app
        self.wallet = wallet
        self.expected_action = expected_action
        self.get_identity_private_key = get_identity_private_key or (
            lambda: _wallet_identity_key(wallet)
        )
        self.get_proof = get_proof or get_proof_from_header_or_body
        self.single_use_store = single_use_store
        self.protocol = protocol
        self.validity_window_ms = validity_window_ms
        self.clock_skew_ms = clock_skew_ms
        self.excluded_paths = excluded_paths or {"/health", "/.well-known/auth"}
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/") or "/"
        if path in self.excluded_paths:
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        if _header_value(headers, PROOF_HEADER) is None and not _has_json_body(
            headers
        ):
            # No proof header and no JSON body that could carry a proof —
            # the request is unauthenticated. This middleware is an
            # authentication gate: reject rather than pass through.
            await _send_json(send, 401, {"error": "missing authentication proof"})
            return

        try:
            body = await read_body_capped(receive, self.max_body_bytes)
        except BodyTooLarge:
            await _send_json(send, 413, {"error": "request body too large"})
            return

        try:
            proof_dict = self.get_proof(body, headers)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            await _send_json(send, 401, {"error": f"malformed proof payload: {exc}"})
            return

        if proof_dict is None:
            await _send_json(send, 401, {"error": "missing authentication proof"})
            return

        try:
            identity_key = verify_auth_proof(
                self.get_identity_private_key(),
                AuthProof.from_dict(proof_dict),
                self.expected_action,
                protocol=self.protocol,
                validity_window_ms=self.validity_window_ms,
                clock_skew_ms=self.clock_skew_ms,
                single_use_store=self.single_use_store,
            )
        except AuthProofError as exc:
            await _send_json(send, 401, {"error": str(exc)})
            return

        scope = dict(scope)
        scope["bsv_auth_proof"] = {"identity_key": identity_key}
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["bsv_auth_proof"] = {"identity_key": identity_key}

        body_consumed = False

        async def replay_receive() -> dict:
            nonlocal body_consumed
            if body_consumed:
                return {"type": "http.disconnect"}
            body_consumed = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def passthrough_send(message: dict) -> None:
            await send(message)

        await self.app(scope, replay_receive, passthrough_send)


def _has_json_body(headers: list[tuple[bytes, bytes]]) -> bool:
    ctype = _header_value(headers, "content-type") or ""
    return ctype.startswith("application/json")


__all__ = [
    "AuthProofMiddleware",
    "PROOF_HEADER",
    "get_proof_from_header_or_body",
]

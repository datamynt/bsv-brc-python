"""
ASGI middleware adapter for bsv.auth (BRC-103/104).

This adapter wraps `bsv.auth.Peer` so that any ASGI application —
Starlette, FastAPI, FastHTML, Litestar, Quart — can speak BRC-103
mutual authentication and BRC-104 HTTP transport without depending
on a specific framework.

Minimal usage:

    from bsv.keys import PrivateKey
    from bsv.wallet.wallet_impl import ProtoWallet
    from bsv_brc.brc104.adapters.asgi import AuthMiddleware

    wallet = ProtoWallet(PrivateKey())  # or load yours from env
    app = AuthMiddleware(your_asgi_app, wallet=wallet)

The middleware exposes a single well-known endpoint:

    POST /.well-known/auth

which handles the BRC-103 handshake (initialRequest, initialResponse,
certificateRequest, certificateResponse). All other paths are passed
through to the wrapped application unchanged.

Wrapping general HTTP traffic with BRC-104 signatures (so every
authenticated request is verified) is intentionally out of scope for
this first cut — it requires reading and rewriting both request and
response bodies and is a separate, larger piece of work. The handshake
endpoint alone is enough for an app to establish a BRC-103 session and
then layer BRC-105 micropayments on top.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import json
import threading
from typing import Any, Awaitable, Callable, Optional

from bsv.auth.auth_message import AuthMessage
from bsv.auth.peer import Peer
from bsv.auth.transports.transport import Transport
from bsv.keys import PublicKey


class _ResultShim(dict):
    """Dict subclass that also exposes its keys as attributes.

    `bsv.auth.Peer` is internally inconsistent: it sometimes does
    ``result.get("error")`` (dict access) and sometimes
    ``result.public_key`` / ``result.signature`` / ``result.valid``
    (attribute access) on the same wallet return value. The wallet
    that ships with `bsv-sdk==2.0.0b1` returns plain dicts, so neither
    style fully works. This shim makes both work simultaneously and
    also normalises the few keys whose names differ between camelCase
    JSON and snake_case Python attributes.
    """

    _ATTR_TO_KEY = {
        "public_key": "publicKey",
        "signature": "signature",
        "valid": "valid",
    }

    def __getattr__(self, item: str) -> Any:
        key = self._ATTR_TO_KEY.get(item, item)
        if key in self:
            value = self[key]
            if item == "public_key" and isinstance(value, str):
                return PublicKey(value)
            return value
        raise AttributeError(item)


def _wrap_result(result: Any) -> Any:
    if result is None or not isinstance(result, dict):
        return result
    if isinstance(result, _ResultShim):
        return result
    return _ResultShim(result)


def _translate_create_signature_args(args: Any) -> Any:
    """Translate Peer's create_signature args to ProtoWallet's expected shape.

    Peer (bsv.auth) emits::

        {
            "encryption_args": {
                "protocol_id": {...},
                "key_id": "...",
                "counterparty": {...},
            },
            "data": b"...",
        }

    ProtoWallet expects flat camelCase::

        {
            "protocolID": {...},
            "keyID": "...",
            "counterparty": {...},
            "data": b"...",
        }

    This is a beta-only mismatch in `bsv-sdk==2.0.0b1`; the shim is
    deliberately small so it can be deleted once upstream lands the
    fix.
    """
    if not isinstance(args, dict):
        return args
    if "encryption_args" not in args:
        return args
    enc = args.get("encryption_args") or {}
    flat: dict = {}
    if "protocol_id" in enc:
        flat["protocolID"] = enc["protocol_id"]
    if "key_id" in enc:
        flat["keyID"] = enc["key_id"]
    if "counterparty" in enc:
        flat["counterparty"] = enc["counterparty"]
    for k, v in args.items():
        if k == "encryption_args":
            continue
        flat[k] = v
    return flat


class _WalletShim:
    """Pass-through wrapper that bridges bsv.auth.Peer and ProtoWallet.

    Two adjustments are applied to the four wallet methods Peer calls:

    1. ``create_signature`` arguments are flattened from
       ``{"encryption_args": {"protocol_id": ...}}`` (the shape Peer
       emits) to ``{"protocolID": ...}`` (the shape ProtoWallet
       accepts).
    2. The dict returned by every method is wrapped in
       :class:`_ResultShim` so Peer's attribute-style reads
       (``result.public_key``, ``result.signature``, ``result.valid``)
       resolve to the same data the dict already carries.

    Every other attribute access is forwarded to the wrapped wallet
    unchanged, so applications can keep using their own wallet
    instance everywhere outside the auth handshake.
    """

    def __init__(self, wallet: Any) -> None:
        self._wallet = wallet

    def get_public_key(self, args: Any = None, originator: str = None) -> Any:
        return _wrap_result(self._wallet.get_public_key(args, originator))

    def create_signature(self, args: Any = None, originator: str = None) -> Any:
        return _wrap_result(
            self._wallet.create_signature(
                _translate_create_signature_args(args), originator
            )
        )

    def verify_signature(self, args: Any = None, originator: str = None) -> Any:
        return _wrap_result(self._wallet.verify_signature(args, originator))

    def acquire_certificate(self, args: Any = None, originator: str = None) -> Any:
        return _wrap_result(self._wallet.acquire_certificate(args, originator))

    def __getattr__(self, item: str) -> Any:
        return getattr(self._wallet, item)

ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]

WELL_KNOWN_AUTH_PATH = "/.well-known/auth"

# Per-request slot used by the capturing transport. Each inbound request
# sets this to a fresh list before invoking Peer; whatever the Peer asks
# the transport to "send" lands in the list and is then serialized as
# the HTTP response body.
_response_slot: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar(
    "bsv_brc_response_slot", default=None
)


class _CapturingTransport(Transport):
    """Transport that captures outbound AuthMessages into a contextvar.

    bsv.auth's `Peer` is built around the assumption that it owns a
    transport which both delivers inbound messages and sends outbound
    ones. On a server, "outbound" really means "the response to the
    HTTP request currently being handled". This transport bridges that
    gap: instead of putting bytes on a socket, it stores the message in
    a per-request contextvar so the surrounding ASGI handler can pick
    it up and write it to the response.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handlers: list = []

    def send(self, message: Any) -> Optional[Exception]:
        slot = _response_slot.get()
        if slot is None:
            return Exception(
                "CapturingTransport.send called outside of an active request"
            )
        slot.append(message)
        return None

    def on_data(self, callback) -> Optional[Exception]:
        if callback is None:
            return Exception("callback cannot be None")
        with self._lock:
            self._handlers.append(callback)
        return None


def _auth_message_from_dict(data: dict) -> AuthMessage:
    """Decode the JSON body of /.well-known/auth into an AuthMessage."""
    identity_key_hex = data.get("identityKey")
    identity_key = PublicKey(identity_key_hex) if identity_key_hex else None

    payload = data.get("payload")
    if isinstance(payload, list):
        payload_bytes: Optional[bytes] = bytes(payload)
    elif isinstance(payload, str) and payload:
        payload_bytes = base64.b64decode(payload)
    else:
        payload_bytes = None

    signature = data.get("signature")
    if isinstance(signature, list):
        signature_bytes: Optional[bytes] = bytes(signature)
    elif isinstance(signature, str) and signature:
        signature_bytes = base64.b64decode(signature)
    else:
        signature_bytes = None

    return AuthMessage(
        version=data.get("version", "0.1"),
        message_type=data.get("messageType", ""),
        identity_key=identity_key,
        nonce=data.get("nonce", "") or "",
        initial_nonce=data.get("initialNonce", "") or "",
        your_nonce=data.get("yourNonce", "") or "",
        certificates=data.get("certificates") or None,
        requested_certificates=data.get("requestedCertificates"),
        payload=payload_bytes,
        signature=signature_bytes,
    )


def _auth_message_to_dict(message: AuthMessage) -> dict:
    """Encode an outbound AuthMessage into the JSON shape bsv.auth uses."""
    identity_key = getattr(message, "identity_key", None)
    if identity_key is not None and hasattr(identity_key, "hex"):
        identity_key_hex = identity_key.hex()
    else:
        identity_key_hex = str(identity_key) if identity_key is not None else None

    payload = getattr(message, "payload", None)
    signature = getattr(message, "signature", None)

    return {
        "version": getattr(message, "version", "0.1"),
        "messageType": getattr(message, "message_type", ""),
        "identityKey": identity_key_hex,
        "nonce": getattr(message, "nonce", "") or "",
        "initialNonce": getattr(message, "initial_nonce", "") or "",
        "yourNonce": getattr(message, "your_nonce", "") or "",
        "certificates": getattr(message, "certificates", None) or [],
        "requestedCertificates": getattr(message, "requested_certificates", None),
        "payload": list(payload) if payload else None,
        "signature": list(signature) if signature else None,
    }


async def _read_body(receive: Callable[[], Awaitable[dict]]) -> bytes:
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        body += message.get("body", b"") or b""
        more_body = message.get("more_body", False)
    return body


async def _send_json(send: Callable[[dict], Awaitable[None]], status: int, payload: dict) -> None:
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


class AuthMiddleware:
    """ASGI middleware that terminates BRC-103 handshakes via bsv.auth.

    Args:
        app: The wrapped ASGI application.
        wallet: A bsv.wallet wallet instance (e.g. ProtoWallet) used as
            the server's identity. The middleware never persists or
            inspects this wallet beyond handing it to bsv.auth.Peer.
        certificates_to_request: Optional RequestedCertificateSet that
            the server should ask clients for during the handshake.
        session_manager: Optional bsv.auth.SessionManager. If omitted,
            Peer creates its own in-memory one.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        wallet: Any,
        certificates_to_request: Any = None,
        session_manager: Any = None,
    ) -> None:
        if wallet is None:
            raise ValueError("AuthMiddleware requires a wallet instance")
        self.app = app
        self.transport = _CapturingTransport()
        self.peer = Peer(
            wallet=_WalletShim(wallet),
            transport=self.transport,
            certificates_to_request=certificates_to_request,
            session_manager=session_manager,
        )

    async def __call__(self, scope: dict, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if scope.get("path") != WELL_KNOWN_AUTH_PATH:
            await self.app(scope, receive, send)
            return

        if scope.get("method", "").upper() != "POST":
            await _send_json(send, 405, {"error": "method not allowed"})
            return

        body = await _read_body(receive)
        if not body:
            await _send_json(send, 400, {"error": "empty body"})
            return

        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            await _send_json(send, 400, {"error": f"invalid json: {exc}"})
            return

        try:
            inbound = _auth_message_from_dict(data)
        except Exception as exc:  # pragma: no cover - defensive
            await _send_json(send, 400, {"error": f"invalid auth message: {exc}"})
            return

        slot: list = []
        token = _response_slot.set(slot)
        try:
            err = await asyncio.to_thread(self.peer.handle_incoming_message, inbound)
        finally:
            _response_slot.reset(token)

        if err is not None:
            await _send_json(send, 401, {"error": str(err)})
            return

        if not slot:
            # No outbound message produced — acknowledge with 204.
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        outbound = slot[0]
        await _send_json(send, 200, _auth_message_to_dict(outbound))


__all__ = ["AuthMiddleware", "WELL_KNOWN_AUTH_PATH"]

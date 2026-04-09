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

from bsv_brc.brc104.core.wire import (
    build_request_payload,
    build_response_payload,
)


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


_AUTH_HEADER_PREFIX = b"x-bsv-auth-"


def _scope_headers(scope: dict) -> list[tuple[str, str]]:
    """Decode an ASGI scope headers list into (lowercase-name, value) tuples."""
    return [
        (k.decode("latin-1").lower(), v.decode("latin-1"))
        for k, v in scope.get("headers", [])
    ]


def _request_has_auth_headers(scope: dict) -> bool:
    for k, _ in scope.get("headers", []):
        if k.lower().startswith(_AUTH_HEADER_PREFIX):
            return True
    return False


def _get_auth_header(scope_headers: list[tuple[str, str]], name: str) -> Optional[str]:
    for k, v in scope_headers:
        if k == name:
            return v
    return None


def _bytes_from_hex_or_b64(value: str) -> bytes:
    """BRC-104 transports signatures as hex; some shipping clients use b64.

    Try hex first, then base64 — both are unambiguous given valid input.
    """
    try:
        return bytes.fromhex(value)
    except ValueError:
        return base64.b64decode(value)


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
            # Non-handshake path: either authenticated general-message
            # wrapping or a plain pass-through. We use the presence of
            # x-bsv-auth-* headers to discriminate so the middleware is
            # safe to drop in front of an existing app without breaking
            # unauthenticated traffic.
            if _request_has_auth_headers(scope):
                await self._handle_general(scope, receive, send)
            else:
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

    async def _handle_general(self, scope: dict, receive, send) -> None:
        """Verify a signed BRC-104 request, run the app, sign the response.

        This is the workhorse path: every authenticated HTTP call from
        a peer that has already completed the /.well-known/auth
        handshake passes through here. The structure mirrors what the
        TS reference implementation does, just expressed in async ASGI:

        1. Read auth headers and reconstruct the bytes the client
           signed (``build_request_payload``).
        2. Hand the resulting AuthMessage to ``Peer.handle_incoming_message``,
           which verifies the signature against the live session.
        3. Forward the request to the wrapped application and buffer
           its full response.
        4. Build the response payload bytes, sign by calling
           ``Peer.to_peer`` (whose outbound message is captured by our
           transport), and emit the original response with the signed
           ``x-bsv-auth-*`` headers added.

        On any verification failure we return 401 and never invoke the
        wrapped application.
        """
        scope_headers = _scope_headers(scope)

        identity_key_hex = _get_auth_header(scope_headers, "x-bsv-auth-identity-key")
        nonce_b64 = _get_auth_header(scope_headers, "x-bsv-auth-nonce")
        your_nonce = _get_auth_header(scope_headers, "x-bsv-auth-your-nonce")
        signature_hex = _get_auth_header(scope_headers, "x-bsv-auth-signature")
        request_id_b64 = _get_auth_header(scope_headers, "x-bsv-auth-request-id")
        version = _get_auth_header(scope_headers, "x-bsv-auth-version") or "0.1"

        if not all([identity_key_hex, nonce_b64, your_nonce, signature_hex, request_id_b64]):
            await _send_json(send, 401, {"error": "incomplete auth headers"})
            return

        try:
            request_nonce_bytes = base64.b64decode(request_id_b64)
        except Exception as exc:
            await _send_json(send, 401, {"error": f"invalid request id: {exc}"})
            return
        if len(request_nonce_bytes) != 32:
            await _send_json(send, 401, {"error": "request id must decode to 32 bytes"})
            return

        try:
            signature_bytes = _bytes_from_hex_or_b64(signature_hex)
        except Exception as exc:
            await _send_json(send, 401, {"error": f"invalid signature: {exc}"})
            return

        try:
            client_identity = PublicKey(identity_key_hex)
        except Exception as exc:
            await _send_json(send, 401, {"error": f"invalid identity key: {exc}"})
            return

        body = await _read_body(receive)

        # Reconstruct the bytes the client signed.
        method = scope.get("method", "GET")
        path = scope.get("path", "/") or "/"
        query = (scope.get("query_string") or b"").decode("latin-1")
        request_payload = build_request_payload(
            request_nonce=request_nonce_bytes,
            method=method,
            url_path=path,
            url_query=query,
            headers=scope_headers,
            body=body,
        )

        inbound = AuthMessage(
            version=version,
            message_type="general",
            identity_key=client_identity,
            nonce=nonce_b64,
            your_nonce=your_nonce,
            payload=request_payload,
            signature=signature_bytes,
        )

        # Verification path: hand the message to Peer. We do not need
        # the capturing transport here because handle_general_message
        # does not call transport.send on success — it only dispatches
        # to general-message callbacks. We still set the slot to
        # absorb any unexpected outbound message rather than crash.
        verify_slot: list = []
        token = _response_slot.set(verify_slot)
        try:
            err = await asyncio.to_thread(
                self.peer.handle_incoming_message, inbound
            )
        finally:
            _response_slot.reset(token)

        if err is not None:
            await _send_json(send, 401, {"error": str(err)})
            return

        # Run the wrapped app and buffer its response so we can sign it.
        captured_response: dict = {"status": 200, "headers": [], "body": bytearray()}
        body_consumed = False

        async def replay_receive() -> dict:
            nonlocal body_consumed
            if body_consumed:
                return {"type": "http.disconnect"}
            body_consumed = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def buffering_send(message: dict) -> None:
            mtype = message.get("type")
            if mtype == "http.response.start":
                captured_response["status"] = message.get("status", 200)
                captured_response["headers"] = list(message.get("headers", []))
            elif mtype == "http.response.body":
                chunk = message.get("body", b"") or b""
                captured_response["body"].extend(chunk)
                # ignore more_body — we always wait for the full body

        await self.app(scope, replay_receive, buffering_send)

        response_status = int(captured_response["status"])
        response_headers_pairs: list[tuple[str, str]] = [
            (k.decode("latin-1").lower(), v.decode("latin-1"))
            for k, v in captured_response["headers"]
        ]
        response_body = bytes(captured_response["body"])

        response_payload = build_response_payload(
            request_nonce=request_nonce_bytes,
            status_code=response_status,
            headers=response_headers_pairs,
            body=response_body,
        )

        # Sign the response payload by asking Peer to send it. Our
        # capturing transport intercepts the AuthMessage so we can pull
        # the signature, server nonce, and identity key out of it.
        sign_slot: list = []
        token = _response_slot.set(sign_slot)
        try:
            send_err = await asyncio.to_thread(
                self.peer.to_peer, response_payload, client_identity, 0
            )
        finally:
            _response_slot.reset(token)

        if send_err is not None or not sign_slot:
            await _send_json(
                send,
                500,
                {"error": f"failed to sign response: {send_err}"},
            )
            return

        outbound: AuthMessage = sign_slot[0]
        server_identity = getattr(outbound, "identity_key", None)
        server_identity_hex = (
            server_identity.hex()
            if hasattr(server_identity, "hex")
            else str(server_identity)
        )
        server_nonce = getattr(outbound, "nonce", "") or ""
        outbound_signature = getattr(outbound, "signature", b"") or b""
        signature_out_hex = (
            outbound_signature.hex()
            if isinstance(outbound_signature, (bytes, bytearray))
            else "".join(f"{b:02x}" for b in outbound_signature)
        )

        # Build the final response headers: keep the wrapped app's
        # headers (minus any conflicting auth headers) and append the
        # signed BRC-104 envelope.
        final_headers: list[tuple[bytes, bytes]] = [
            (k, v)
            for k, v in captured_response["headers"]
            if not k.lower().startswith(_AUTH_HEADER_PREFIX)
        ]
        final_headers.extend(
            [
                (b"x-bsv-auth-version", version.encode("latin-1")),
                (b"x-bsv-auth-identity-key", server_identity_hex.encode("latin-1")),
                (b"x-bsv-auth-message-type", b"general"),
                (b"x-bsv-auth-nonce", server_nonce.encode("latin-1")),
                (b"x-bsv-auth-your-nonce", nonce_b64.encode("latin-1")),
                (b"x-bsv-auth-signature", signature_out_hex.encode("latin-1")),
                (b"x-bsv-auth-request-id", request_id_b64.encode("latin-1")),
            ]
        )

        await send(
            {
                "type": "http.response.start",
                "status": response_status,
                "headers": final_headers,
            }
        )
        await send(
            {"type": "http.response.body", "body": response_body, "more_body": False}
        )


__all__ = ["AuthMiddleware", "WELL_KNOWN_AUTH_PATH"]

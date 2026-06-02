"""
High-level glue that turns the bsv-brc middleware into a deployable app.

The individual middlewares are powerful but unopinionated: a developer
still has to stack BRC-103/104 auth (``AuthMiddleware``) under BRC-105
payments (``PaymentMiddleware``), and — the genuinely error-prone part —
hand-roll the BRC-29 derivation prefix/suffix into
``wallet.internalize_action`` to actually settle a received payment.

This module removes that friction:

- :func:`build_internalize_args` — the pure, testable BRC-29 mapping
  from a client's ``BSVPayment`` to the ``internalize_action`` args.
- :func:`make_internalize_verifier` — a ready ``verify_payment``
  callback that settles payments through any bsv-sdk wallet.
- :func:`build_brc_app` — wraps your ASGI app with auth + payments
  pre-stacked in the correct order.
- :class:`PathPricing`, :func:`get_identity`, :func:`get_payment` —
  small ergonomics for per-route pricing and reading the verified
  identity / payment result downstream.

Requires the ``starlette`` extra (``pip install "bsv-brc[starlette]"``)
because :class:`PaymentMiddleware` is a Starlette middleware.

References:
    BRC-29:  https://bsv.brc.dev/payments/0029
    BRC-105: https://bsv.brc.dev/payments/0105
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import Any, Awaitable, Callable, Mapping, Optional

from bsv_brc.brc104.adapters.asgi import AuthMiddleware
from bsv_brc.brc105.middleware import PaymentMiddleware
from bsv_brc.brc105.nonce import NonceManager
from bsv_brc.brc105.types import (
    BSVPayment,
    PaymentResult,
    PricingStrategy,
    StaticPricing,
)

__all__ = [
    "build_internalize_args",
    "make_internalize_verifier",
    "build_brc_app",
    "PathPricing",
    "get_identity",
    "get_payment",
]

# Protocol tag BRC-29 uses to mark a wallet-payment output's remittance.
WALLET_PAYMENT_PROTOCOL = "wallet payment"


def build_internalize_args(
    payment: BSVPayment,
    sender_identity_key: str,
    *,
    output_index: int = 0,
    description: str = "BRC-105 payment",
) -> dict[str, Any]:
    """Map a client ``BSVPayment`` to ``wallet.internalize_action`` args.

    This is the BRC-29 wiring that the BRC-105 docs call the single
    hardest hand-rolled step. The client built a transaction paying the
    server and disclosed the derivation prefix/suffix it used; the
    server replays them so its wallet can derive the locking key, claim
    the output, and broadcast.

    Args:
        payment: the parsed ``x-bsv-payment`` body.
        sender_identity_key: the authenticated sender's identity key
            (hex), from the BRC-103/104 handshake.
        output_index: which output of the payment transaction pays this
            server (the BRC-29 convention is 0).
        description: human-readable label stored with the action.

    Returns:
        A dict ready to pass to ``wallet.internalize_action(args)``.
    """
    tx_bytes = base64.b64decode(payment.transaction)
    return {
        "tx": tx_bytes,
        "outputs": [
            {
                "outputIndex": output_index,
                "protocol": WALLET_PAYMENT_PROTOCOL,
                "paymentRemittance": {
                    "derivationPrefix": payment.derivation_prefix,
                    "derivationSuffix": payment.derivation_suffix,
                    "senderIdentityKey": sender_identity_key,
                },
            }
        ],
        "description": description,
    }


def _payment_total_satoshis(tx_bytes: bytes) -> int:
    """Best-effort sum of the payment transaction's output values.

    Used only to populate the informational
    ``x-bsv-payment-satoshis-paid`` response header. It is the tx's
    total output value, which for a real payment includes change, so
    treat it as indicative rather than the exact fee to this server.
    Returns 0 if the bytes cannot be parsed as BEEF.
    """
    try:
        from bsv.transaction import Transaction

        tx = Transaction.from_beef(tx_bytes)
        return sum(int(getattr(o, "satoshis", 0) or 0) for o in tx.outputs)
    except Exception:
        return 0


def make_internalize_verifier(
    wallet: Any,
    *,
    description: str = "BRC-105 payment",
    output_index: int = 0,
    report_satoshis: bool = True,
) -> Callable[[BSVPayment, str], Awaitable[PaymentResult]]:
    """Build a ``verify_payment`` callback that settles via ``wallet``.

    The returned coroutine maps the payment to BRC-29 internalize args
    (:func:`build_internalize_args`), calls
    ``wallet.internalize_action`` off the event loop, and reports the
    outcome as a :class:`PaymentResult`. Pass it straight to
    :func:`build_brc_app` or :class:`PaymentMiddleware`.

    The wallet's ``internalize_action`` typically broadcasts the
    transaction, so this performs network I/O when used against a live
    wallet.

    IMPORTANT — wallet must accept AtomicBEEF. ``BSVPayment.transaction``
    is base64 AtomicBEEF (per BRC-29), and that is what this passes as
    the ``tx`` arg. The wallet's ``internalize_action`` must therefore
    decode AtomicBEEF. The ``ProtoWallet`` shipped in ``bsv-sdk==2.0.0b1``
    does NOT: its internalize path parses ``tx`` as a *raw* transaction
    (``Transaction.from_reader``) and will silently mis-decode the BEEF
    header, potentially broadcasting corrupt bytes. Use a wallet whose
    ``internalize_action`` is BEEF-aware (e.g. wallet-toolbox), or supply
    your own ``verify_payment``. (Tracked upstream as a py-sdk bug.)
    """

    async def verify_payment(
        payment: BSVPayment, identity_key: str
    ) -> PaymentResult:
        args = build_internalize_args(
            payment,
            identity_key,
            output_index=output_index,
            description=description,
        )
        result = await asyncio.to_thread(wallet.internalize_action, args)

        accepted = bool(_result_field(result, "accepted", False))
        if not accepted:
            error = _result_field(result, "error", None)
            if error:
                raise ValueError(str(error))

        satoshis = _payment_total_satoshis(args["tx"]) if report_satoshis else 0
        return PaymentResult(
            satoshis_paid=satoshis,
            accepted=accepted,
            tx=_result_field(result, "txid", None),
        )

    return verify_payment


def _result_field(result: Any, key: str, default: Any) -> Any:
    """Read ``key`` from a dict-or-object wallet result."""
    if isinstance(result, Mapping):
        return result.get(key, default)
    return getattr(result, key, default)


def build_brc_app(
    app: Any,
    *,
    wallet: Any,
    pricing: Optional[PricingStrategy] = None,
    verify_payment: Optional[Callable[[BSVPayment, str], Awaitable[PaymentResult]]] = None,
    nonce_manager: Optional[NonceManager] = None,
    nonce_secret: Optional[bytes] = None,
    certificates_to_request: Any = None,
    session_manager: Any = None,
    excluded_paths: Optional[set[str]] = None,
) -> AuthMiddleware:
    """Wrap an ASGI app with BRC-103/104 auth + BRC-105 payments.

    Middleware order is ``AuthMiddleware(PaymentMiddleware(app))`` so the
    handshake at ``/.well-known/auth`` is terminated first and the
    verified sender identity is available when payment is checked.

    Args:
        app: your inner ASGI application.
        wallet: the server's bsv-sdk wallet (identity + payment settle).
        pricing: how much each request costs; defaults to
            ``StaticPricing(0)`` (zero satoshis). Note this means *no
            payment*, NOT open access: every path except
            ``excluded_paths`` still requires a completed BRC-103
            handshake at ``/.well-known/auth`` and a signed BRC-104
            request — a bare ``GET /`` returns 401. To expose a genuinely
            public endpoint, list it in ``excluded_paths``. Use
            :class:`PathPricing` or your own strategy to charge.
        verify_payment: payment settlement callback; defaults to
            :func:`make_internalize_verifier` over ``wallet``.
        nonce_manager: BRC-105 derivation-prefix manager; one is created
            from ``nonce_secret`` (or a random secret) if omitted.
        nonce_secret: secret for the default NonceManager. Provide a
            stable value in production so prefixes survive restarts.
        certificates_to_request / session_manager: forwarded to
            :class:`AuthMiddleware`.
        excluded_paths: paths that skip payment (health checks, etc.).

    Returns:
        An ASGI app (the outer :class:`AuthMiddleware`).
    """
    if pricing is None:
        pricing = StaticPricing(0)
    if nonce_manager is None:
        # A random secret works but does not survive a restart, so
        # outstanding 402 challenges are invalidated on redeploy. Pass a
        # stable nonce_secret (or your own NonceManager) in production.
        nonce_manager = NonceManager(secret=nonce_secret or os.urandom(32))
    if verify_payment is None:
        verify_payment = make_internalize_verifier(wallet)

    paid = PaymentMiddleware(
        app,
        nonce_manager=nonce_manager,
        pricing=pricing,
        verify_payment=verify_payment,
        excluded_paths=excluded_paths,
    )
    return AuthMiddleware(
        paid,
        wallet=wallet,
        certificates_to_request=certificates_to_request,
        session_manager=session_manager,
    )


class PathPricing(PricingStrategy):
    """Per-path pricing: map exact request paths to satoshi prices.

    Paths not in the map cost ``default`` satoshis (0 = free).

    Example::

        PathPricing({"/premium": 100, "/report": 500}, default=0)
    """

    def __init__(self, prices: Mapping[str, int], *, default: int = 0) -> None:
        self._prices = dict(prices)
        self._default = default

    async def calculate_price(self, request: Any) -> int:
        path = getattr(getattr(request, "url", None), "path", None)
        return self._prices.get(path, self._default)


def get_identity(request: Any) -> Optional[str]:
    """Return the authenticated sender identity key (hex), or None.

    Reads what :class:`AuthMiddleware` placed in the ASGI scope after a
    verified BRC-104 request.
    """
    scope = getattr(request, "scope", request)
    auth = scope.get("bsv_auth") if isinstance(scope, Mapping) else None
    if auth:
        return auth.get("identity_key")
    # Fall back to the inbound header (set by the client) during the request.
    try:
        return request.headers.get("x-bsv-auth-identity-key")
    except Exception:
        return None


def get_payment(request: Any) -> Optional[PaymentResult]:
    """Return the :class:`PaymentResult` attached by PaymentMiddleware."""
    state = getattr(request, "state", None)
    return getattr(state, "payment", None) if state is not None else None

"""
BRC-87: standardized naming for overlay topic managers and lookup services.

Validate ``tm_*`` topic names and ``ls_*`` lookup-service names against
the BRC-87 master rules so a bad name fails fast — before it reaches the
wire, a SHIP/SLAP advertisement, or another node that would silently
reject it. Names that violate the rules are a hard-to-debug class of
interop failure; this turns them into an immediate, local error.

Master rules (https://bsv.brc.dev/overlays/0087):

1. Only lower-case letters and underscores (no digits, no upper-case).
2. Must not start or end with an underscore.
3. No consecutive underscores.
4. No longer than 50 characters.

Topic managers use the ``tm_`` prefix; lookup services use ``ls_``.
Examples: ``tm_uhrp_files``, ``ls_tempo_songs_search``.

Pure-stdlib; safe to import without any optional dependency.
"""

from __future__ import annotations

import re

__all__ = [
    "TOPIC_PREFIX",
    "SERVICE_PREFIX",
    "MAX_NAME_LENGTH",
    "InvalidNameError",
    "validate_overlay_name",
    "validate_topic_name",
    "validate_service_name",
    "is_valid_overlay_name",
    "is_valid_topic_name",
    "is_valid_service_name",
]

TOPIC_PREFIX = "tm_"
SERVICE_PREFIX = "ls_"
MAX_NAME_LENGTH = 50

# Prefix, then a descriptor of lower-case-letter words joined by single
# underscores. The prefix supplies the only required underscore and the
# descriptor must be non-empty, so this enforces all four master rules
# except length (checked separately for a clearer message): no
# digits/upper-case (only [a-z]), no consecutive underscores (every "_"
# is followed by [a-z]+), and no leading/trailing underscore.
_NAME_RE = re.compile(r"^(?:tm|ls)_[a-z]+(?:_[a-z]+)*$")


class InvalidNameError(ValueError):
    """Raised when an overlay name violates the BRC-87 master rules."""


def validate_overlay_name(name: str, *, kind: str | None = None) -> str:
    """Validate a BRC-87 overlay name, returning it unchanged if valid.

    Args:
        name: the topic or service name to check.
        kind: ``"topic"`` to require the ``tm_`` prefix, ``"service"``
            to require ``ls_``, or ``None`` to accept either.

    Returns:
        ``name`` unchanged when valid.

    Raises:
        InvalidNameError: with a specific reason when invalid.
    """
    if not isinstance(name, str):
        raise InvalidNameError(f"name must be a string, got {type(name).__name__}")
    if len(name) > MAX_NAME_LENGTH:
        raise InvalidNameError(
            f"name {name!r} is {len(name)} characters; the maximum is "
            f"{MAX_NAME_LENGTH}"
        )
    if kind == "topic" and not name.startswith(TOPIC_PREFIX):
        raise InvalidNameError(
            f"topic name {name!r} must start with {TOPIC_PREFIX!r}"
        )
    if kind == "service" and not name.startswith(SERVICE_PREFIX):
        raise InvalidNameError(
            f"service name {name!r} must start with {SERVICE_PREFIX!r}"
        )
    if not _NAME_RE.match(name):
        raise InvalidNameError(
            f"name {name!r} is not a valid BRC-87 name: it must start with "
            f"'tm_' or 'ls_' and then use lower-case letters in "
            f"underscore-separated words — no digits, upper-case, or "
            f"leading/trailing/consecutive underscores"
        )
    return name


def validate_topic_name(name: str) -> str:
    """Validate a ``tm_*`` topic-manager name (see :func:`validate_overlay_name`)."""
    return validate_overlay_name(name, kind="topic")


def validate_service_name(name: str) -> str:
    """Validate an ``ls_*`` lookup-service name (see :func:`validate_overlay_name`)."""
    return validate_overlay_name(name, kind="service")


def is_valid_overlay_name(name: str, *, kind: str | None = None) -> bool:
    """Boolean form of :func:`validate_overlay_name` (never raises)."""
    try:
        validate_overlay_name(name, kind=kind)
        return True
    except InvalidNameError:
        return False


def is_valid_topic_name(name: str) -> bool:
    """True if ``name`` is a valid ``tm_*`` topic name."""
    return is_valid_overlay_name(name, kind="topic")


def is_valid_service_name(name: str) -> bool:
    """True if ``name`` is a valid ``ls_*`` lookup-service name."""
    return is_valid_overlay_name(name, kind="service")

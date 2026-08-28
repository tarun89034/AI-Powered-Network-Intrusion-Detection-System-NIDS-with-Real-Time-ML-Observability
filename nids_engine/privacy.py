"""
Privacy Module
Pseudonymizes network identifiers before they leave the engine.

The dashboard used to hash IP addresses in the browser, which meant every raw
address still crossed the WebSocket and the REST API in plaintext -- the
anonymization was cosmetic, not protective. Scrubbing here keeps raw addresses
inside the engine's trust boundary (capture, feature extraction, inference and
the local SQLite store) and never puts them on the wire.
"""

import hmac
import logging
import os
import re
import secrets
from hashlib import sha256
from typing import Any, Dict, Optional

logger = logging.getLogger("nids.privacy")

ANON_PREFIX = "Anon-"
_DIGEST_LENGTH = 6

# Fields that hold a bare address, and fields that embed addresses in a larger
# string (flow_id looks like "10.0.0.1:443-10.0.0.2:1234-TCP").
_ADDRESS_FIELDS = frozenset({"src_ip", "dst_ip", "ip"})
_EMBEDDED_ADDRESS_FIELDS = frozenset({"flow_id"})

# The capture path drops anything that is not IPv4 (see PacketParser), so an
# IPv4 literal is the only address form that can reach a payload.
_IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_DISABLED_VALUES = {"0", "off", "false", "no"}

_ephemeral_salt: Optional[bytes] = None
_warned_about_salt = False


def privacy_enabled() -> bool:
    """Privacy mode is on unless NIDS_PRIVACY_MODE explicitly disables it."""
    return os.getenv("NIDS_PRIVACY_MODE", "on").strip().lower() not in _DISABLED_VALUES


def _salt() -> bytes:
    """Returns the HMAC salt, generating a per-process one if none is set.

    A configured NIDS_ANON_SALT keeps pseudonyms stable across restarts so the
    dashboard can still correlate a talker over time; without one the mapping
    is thrown away when the process exits.
    """
    global _ephemeral_salt, _warned_about_salt

    configured = os.getenv("NIDS_ANON_SALT")
    if configured:
        return configured.encode("utf-8")

    if _ephemeral_salt is None:
        _ephemeral_salt = secrets.token_bytes(32)
        if not _warned_about_salt:
            logger.warning(
                "NIDS_ANON_SALT is not set; using an ephemeral salt. "
                "Pseudonyms will not be stable across restarts."
            )
            _warned_about_salt = True

    return _ephemeral_salt


def anonymize_ip(address: str) -> str:
    """Maps an address to a stable, one-way pseudonym such as 'Anon-3f9c2a'."""
    if address.startswith(ANON_PREFIX):
        return address  # already scrubbed; keep scrub() idempotent
    digest = hmac.new(_salt(), address.encode("utf-8"), sha256).hexdigest()
    return f"{ANON_PREFIX}{digest[:_DIGEST_LENGTH]}"


def anonymize_embedded(value: str) -> str:
    """Replaces every address literal inside a larger string."""
    return _IPV4_PATTERN.sub(lambda match: anonymize_ip(match.group(0)), value)


def scrub(payload: Any) -> Any:
    """Returns a copy of payload with all network addresses pseudonymized.

    Walks nested dicts/lists so a single call covers flows, alerts and the
    top-talker lists inside a stats block. A no-op when privacy mode is off.
    """
    if not privacy_enabled():
        return payload
    return _scrub(payload)


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        scrubbed: Dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(item, str) and key in _ADDRESS_FIELDS:
                scrubbed[key] = anonymize_ip(item)
            elif isinstance(item, str) and key in _EMBEDDED_ADDRESS_FIELDS:
                scrubbed[key] = anonymize_embedded(item)
            else:
                scrubbed[key] = _scrub(item)
        return scrubbed

    if isinstance(value, list):
        return [_scrub(item) for item in value]

    return value

# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""HMAC-SHA256 request signing for the ERPNext -> Brew93 events channel.

Contract (see docs/INTEGRATION_CONTRACT.md, §15/16):

    signature = HMAC_SHA256(secret, f"{timestamp}.{raw_body}")

sent as headers::

    X-Brew93-Timestamp: <unix seconds>
    X-Brew93-Signature: v1=<lowercase hex>
    X-Brew93-Event-Id:  <event_id, equal to the body's event_id>
    Content-Type:       application/json

Rules this module enforces, so the sender can never get them subtly wrong:
- We sign the EXACT bytes we transmit. `build_signed_headers` takes the raw body
  bytes and returns headers for those same bytes; the caller must POST `raw_body`
  unchanged (no re-serialisation between signing and sending).
- The signature covers the timestamp, so a stored signature cannot be replayed
  with a fresh timestamp. Callers MUST re-sign on every retry -> `build_signed_headers`
  is cheap and is called per attempt.
- The secret is passed in by the caller (read from settings/site_config); this
  module never reads, stores, or logs it.

Pure standard library. No Frappe import, so it is unit-testable in isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_VERSION = "v1"

HEADER_TIMESTAMP = "X-Brew93-Timestamp"
HEADER_SIGNATURE = "X-Brew93-Signature"
HEADER_EVENT_ID = "X-Brew93-Event-Id"


def _as_bytes(raw_body: str | bytes) -> bytes:
    if isinstance(raw_body, bytes):
        return raw_body
    return raw_body.encode("utf-8")


def signing_string(timestamp: int, raw_body: str | bytes) -> bytes:
    """The exact byte string that gets HMAC'd: ``b"<ts>." + raw_body``."""
    return str(int(timestamp)).encode("ascii") + b"." + _as_bytes(raw_body)


def compute_signature(secret: str, timestamp: int, raw_body: str | bytes) -> str:
    """Return the lowercase hex HMAC-SHA256 of ``"{timestamp}.{raw_body}"``."""
    if not secret:
        raise ValueError("HMAC secret is required to sign an event")
    mac = hmac.new(_as_bytes(secret), signing_string(timestamp, raw_body), hashlib.sha256)
    return mac.hexdigest()


def build_signed_headers(
    secret: str,
    raw_body: str | bytes,
    event_id: str,
    timestamp: int | None = None,
) -> dict[str, str]:
    """Build the signed request headers for `raw_body`.

    Call this once per delivery attempt with a fresh (default) timestamp so that
    a retry outside the replay window still verifies.
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    sig = compute_signature(secret, ts, raw_body)
    return {
        "Content-Type": "application/json",
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: f"{SIGNATURE_VERSION}={sig}",
        HEADER_EVENT_ID: event_id,
    }


def verify_signature(
    secret: str,
    raw_body: str | bytes,
    timestamp_header: str,
    signature_header: str,
    replay_window_seconds: int = 300,
    now: int | None = None,
) -> tuple[bool, str]:
    """Verify an inbound signed request (used by the inbound receiver + tests).

    Returns ``(ok, reason)``. On failure `reason` is a short machine-stable code:
    ``bad_timestamp`` | ``expired`` | ``bad_signature_format`` | ``signature_mismatch``.
    Uses constant-time comparison. Never logs the secret or the signature.
    """
    try:
        ts = int(timestamp_header)
    except (TypeError, ValueError):
        return False, "bad_timestamp"

    current = int(time.time()) if now is None else int(now)
    if abs(current - ts) > int(replay_window_seconds):
        return False, "expired"

    if not signature_header or "=" not in signature_header:
        return False, "bad_signature_format"
    version, _, provided = signature_header.partition("=")
    if version != SIGNATURE_VERSION or not provided:
        return False, "bad_signature_format"

    expected = compute_signature(secret, ts, raw_body)
    if not hmac.compare_digest(expected, provided.strip().lower()):
        return False, "signature_mismatch"
    return True, "ok"

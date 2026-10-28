"""Signed application audit evidence persisted in the caller's transaction."""

import base64
import binascii
from collections.abc import Mapping
import json
import re
from sqlite3 import Connection
from typing import Any

from cryptography.exceptions import InvalidSignature

from .config import normalize_ip
from .crypto import canonical_bytes
from .identity import KeyRing


_FIELDS = (
    "domain", "event_id", "time_us", "kind", "src_ip", "dst_ip", "dst_port",
    "username", "session_ref", "record_id", "outcome",
)
_KINDS = frozenset({
    "login_failure", "login_success", "admin_login_failure", "admin_login_success",
    "login_restricted_attempt",
    "record_created", "record_updated", "record_read", "foreign_record_denied",
    "integrity_failure", "blocked_request", "logout", "admin_block", "admin_unblock",
})


def _normalized_payload(payload: dict) -> dict:
    """Validate the allowlist before any secret-bearing extras can be signed."""
    if not isinstance(payload, dict) or set(payload) != set(_FIELDS):
        raise ValueError("Invalid application event fields")
    value = dict(payload)
    if value["domain"] != "live":
        raise ValueError("Invalid application event domain")
    event_id = value["event_id"]
    if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-f]{32}", event_id) is None:
        raise ValueError("Invalid application event ID")
    if type(value["time_us"]) is not int:
        raise ValueError("Invalid application event timestamp")
    if not isinstance(value["kind"], str) or value["kind"] not in _KINDS:
        raise ValueError("Invalid application event kind")
    for field in ("username", "session_ref", "record_id"):
        if value[field] is not None and not isinstance(value[field], str):
            raise ValueError("Invalid application event context")
    if not isinstance(value["outcome"], str):
        raise ValueError("Invalid application event outcome")
    if value["kind"] == "login_restricted_attempt" and value["outcome"] != "login_restricted_attempt":
        raise ValueError("Invalid restricted login outcome")
    port = value["dst_port"]
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("Invalid application event destination port")

    source = value["src_ip"]
    try:
        value["src_ip"] = normalize_ip(source) if isinstance(source, str) else "unknown"
    except ValueError:
        # An unavailable actual peer remains unavailable; no header substitutes it.
        value["src_ip"] = "unknown"
    destination = value["dst_ip"]
    if destination is not None:
        if not isinstance(destination, str):
            raise ValueError("Invalid application event destination")
        try:
            value["dst_ip"] = normalize_ip(destination)
        except ValueError:
            raise ValueError("Invalid application event destination") from None
    return value


def append_app_event(conn: Connection, keys: KeyRing, payload: dict) -> str:
    """Validate, normalize, sign and insert an event without committing."""
    value = _normalized_payload(payload)
    event_id = value["event_id"]
    if conn.execute(
        "SELECT 1 FROM events WHERE domain=? AND event_id=?",
        (value["domain"], event_id),
    ).fetchone() is not None:
        return event_id

    data = canonical_bytes(value)
    signature = base64.b64encode(keys.signing_key.sign(data)).decode("ascii")
    inserted = conn.execute(
        "INSERT INTO events (domain,event_id,time_us,kind,src_ip,dst_ip,dst_port,"
        "username,session_ref,record_id,outcome,payload_json,signature_b64) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(domain,event_id) DO NOTHING",
        tuple(value[field] for field in _FIELDS) + (data.decode("utf-8"), signature),
    )
    if inserted.rowcount == 1:
        from .rules import evaluate_event

        evaluate_event(conn, keys, value["domain"], event_id)
    return event_id


def verify_app_event(keys: KeyRing, row: Mapping[str, Any]) -> bool:
    """Verify signed application evidence and its indexed column agreement."""
    try:
        stored_json = row["payload_json"]
        if not isinstance(stored_json, str):
            return False
        payload = json.loads(stored_json)
        normalized = _normalized_payload(payload)
        # Verification never repairs malformed signed evidence into acceptance.
        if normalized != payload:
            return False
        data = canonical_bytes(payload)
        if stored_json.encode("utf-8") != data:
            return False
        for field in _FIELDS:
            indexed = row[field]
            if type(indexed) is not type(payload[field]) or indexed != payload[field]:
                return False
        signature_text = row["signature_b64"]
        if not isinstance(signature_text, str):
            return False
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
            return False
        keys.signing_key.public_key().verify(signature, data)
        return True
    except (
        KeyError, IndexError, TypeError, ValueError, UnicodeError,
        binascii.Error, InvalidSignature, OverflowError, RecursionError,
    ):
        return False

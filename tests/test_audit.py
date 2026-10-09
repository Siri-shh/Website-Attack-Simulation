"""Audit evidence contracts against real SQLite and Ed25519 keys."""

import base64
from contextlib import closing
from dataclasses import replace
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from security_lab.audit import append_app_event, verify_app_event
from security_lab.db import connect, transaction


FIELDS = {
    "domain", "event_id", "time_us", "kind", "src_ip", "dst_ip", "dst_port",
    "username", "session_ref", "record_id", "outcome",
}
KINDS = [
    "login_failure", "login_success", "admin_login_failure", "admin_login_success",
    "record_created", "record_updated", "record_read", "foreign_record_denied",
    "integrity_failure", "blocked_request", "logout", "admin_block", "admin_unblock",
]


def payload(**changes):
    value = {
        "domain": "live", "event_id": "0123456789abcdef0123456789abcdef",
        "time_us": 1_700_000_000_123_456, "kind": "login_success",
        "src_ip": "172.29.0.10", "dst_ip": "172.29.0.20", "dst_port": 8443,
        "username": "bob", "session_ref": "opaque-session-reference",
        "record_id": None, "outcome": "login_ok",
    }
    value.update(changes)
    return value


def encoded(value):
    # Independent oracle: never serialize expected bytes with audit's helpers.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signed_row(keys, value=None):
    """Supply genuine signed evidence independently of append_app_event."""
    value = payload() if value is None else value
    raw = encoded(value)
    return dict(value, seq=1, payload_json=raw.decode("utf-8"),
                signature_b64=base64.b64encode(keys.signing_key.sign(raw)).decode("ascii"),
                capture_id=None, frame_number=None)


def load_event(conn):
    return conn.execute("SELECT * FROM events WHERE domain='live'").fetchone()


def test_persisted_payload_is_canonical_signed_and_complete(config, keys):
    value = payload(username="Café नमस्ते")
    before = dict(value)
    with transaction(config) as conn:
        assert append_app_event(conn, keys, value) == value["event_id"]
        row = load_event(conn)
        assert row is not None
        assert {field: row[field] for field in FIELDS} == value
        assert set(json.loads(row["payload_json"])) == FIELDS
        assert row["payload_json"].encode("utf-8") == encoded(value)
        signature = base64.b64decode(row["signature_b64"], validate=True)
        assert len(signature) == 64
        keys.signing_key.public_key().verify(signature, encoded(value))
        assert row["capture_id"] is None and row["frame_number"] is None
        assert verify_app_event(keys, row) is True
    assert value == before
    with closing(connect(config)) as conn:
        assert verify_app_event(keys, load_event(conn)) is True


@pytest.mark.parametrize("kind", KINDS)
def test_all_declared_application_kinds_can_be_persisted(config, keys, kind):
    with transaction(config) as conn:
        append_app_event(conn, keys, payload(kind=kind))
        assert load_event(conn)["kind"] == kind
        assert verify_app_event(keys, load_event(conn)) is True


def test_nullable_event_context(config, keys):
    value = payload(dst_ip=None, dst_port=None, username=None, session_ref=None, record_id=None)
    with transaction(config) as conn:
        append_app_event(conn, keys, value)
        assert verify_app_event(keys, load_event(conn)) is True
        assert json.loads(load_event(conn)["payload_json"]) == value


@pytest.mark.parametrize(("source", "expected"), [
    ("::ffff:172.29.0.10", "172.29.0.10"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("unknown", "unknown"), ("invalid-peer", "unknown"), (None, "unknown"),
])
def test_source_normalization_is_in_the_signed_payload(config, keys, source, expected):
    value = payload(src_ip=source, dst_ip="::ffff:172.29.0.20")
    before = dict(value)
    with transaction(config) as conn:
        append_app_event(conn, keys, value)
        row = load_event(conn)
        saved = json.loads(row["payload_json"])
        assert row["src_ip"] == saved["src_ip"] == expected
        assert row["dst_ip"] == saved["dst_ip"] == "172.29.0.20"
        assert verify_app_event(keys, row) is True
    assert value == before


def test_identical_event_id_is_a_noop_and_never_resigned(config, keys):
    with transaction(config) as conn:
        event_id = append_app_event(conn, keys, payload())
        before = dict(load_event(conn))

        class NoSigning:
            def sign(self, data):
                raise AssertionError("Replay must not regenerate signed evidence")

        replay_keys = replace(keys, signing_key=NoSigning())
        assert append_app_event(conn, replay_keys, payload()) == event_id
        assert append_app_event(conn, replay_keys, payload(username="alice")) == event_id
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert dict(load_event(conn)) == before


def test_append_does_not_commit_callers_transaction(config, keys):
    with closing(connect(config)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        append_app_event(conn, keys, payload())
        assert conn.in_transaction
        assert load_event(conn) is not None
        with closing(connect(config)) as observer:
            assert load_event(observer) is None
        conn.rollback()
    with closing(connect(config)) as observer:
        assert load_event(observer) is None


@pytest.mark.parametrize("field", ["password", "title", "body", "cookies", "private_key", "form"])
def test_extra_sensitive_fields_are_rejected_without_persistence(config, keys, field):
    with transaction(config) as conn:
        with pytest.raises(ValueError) as caught:
            append_app_event(conn, keys, payload(**{field: "SENSITIVE_TEST_VALUE"}))
        assert "SENSITIVE_TEST_VALUE" not in str(caught.value)
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


@pytest.mark.parametrize(("field", "value"), [
    ("domain", "offline:deadbeef"), ("event_id", "not-a-uuid"),
    ("event_id", "ABCDEF0123456789ABCDEF0123456789"),
    ("time_us", True), ("time_us", "1700000000123456"),
    ("kind", "packet_syn"), ("kind", "invented-outcome"),
    ("dst_ip", "not-an-ip"), ("dst_port", 0), ("dst_port", 65536),
    ("dst_port", True), ("username", {"password": "secret"}),
    ("session_ref", ["cookie"]), ("record_id", 7), ("outcome", None),
])
def test_invalid_payload_shape_or_type_is_rejected(config, keys, field, value):
    with transaction(config) as conn:
        with pytest.raises(ValueError):
            append_app_event(conn, keys, payload(**{field: value}))
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_missing_payload_field_is_rejected(config, keys):
    value = payload()
    del value["record_id"]
    with transaction(config) as conn:
        with pytest.raises(ValueError):
            append_app_event(conn, keys, value)
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


@pytest.mark.parametrize("field", sorted(FIELDS))
def test_every_indexed_column_must_agree_with_signed_payload(keys, field):
    row = signed_row(keys)
    row[field] = row[field] + 1 if type(row[field]) is int else "tampered"
    assert verify_app_event(keys, row) is False


def test_changed_payload_or_signature_or_wrong_key_is_rejected(keys):
    row = signed_row(keys)
    assert verify_app_event(keys, row) is True
    edited = json.loads(row["payload_json"])
    edited["username"] = "alice"
    assert verify_app_event(keys, dict(row, payload_json=encoded(edited).decode())) is False
    signature = bytearray(base64.b64decode(row["signature_b64"]))
    signature[0] ^= 1
    assert verify_app_event(keys, dict(row, signature_b64=base64.b64encode(signature).decode())) is False
    wrong_keys = replace(keys, signing_key=Ed25519PrivateKey.generate())
    assert verify_app_event(wrong_keys, row) is False


@pytest.mark.parametrize("changes", [
    {"password": "secret"}, {"kind": "packet_syn"}, {"domain": "offline:abc"},
    {"src_ip": "::ffff:172.29.0.10"}, {"src_ip": "not-an-ip"},
    {"dst_ip": "::ffff:172.29.0.20"}, {"time_us": True},
    {"dst_port": True}, {"username": {"password": "secret"}},
])
def test_authentic_signature_cannot_authorize_invalid_or_unnormalized_payload(keys, changes):
    row = signed_row(keys, payload(**changes))
    assert verify_app_event(keys, row) is False


@pytest.mark.parametrize(("field", "value"), [
    ("payload_json", "not JSON"), ("payload_json", "[]"),
    ("payload_json", None), ("signature_b64", None),
    ("signature_b64", "!invalid!"), ("signature_b64", "YWJj"),
])
def test_malformed_stored_evidence_returns_false(keys, field, value):
    assert verify_app_event(keys, dict(signed_row(keys), **{field: value})) is False


def test_missing_indexed_or_evidence_field_returns_false(keys):
    for field in FIELDS | {"payload_json", "signature_b64"}:
        row = signed_row(keys)
        del row[field]
        assert verify_app_event(keys, row) is False

"""Public cryptographic contracts, including exact measured operation scopes."""

import base64
from dataclasses import replace
import hashlib
import json
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

from security_lab import crypto
from security_lab.crypto import IntegrityError, canonical_bytes, open_record, seal_record


TITLE = "  Café — नमस्ते 🌍\n"
BODY = "秘密の本文\nLine two\t<keep & content>\n  "
FIELDS = {
    "id", "owner", "version", "nonce_b64", "ciphertext_b64", "sha256_hex",
    "signature_b64", "created_at_us", "updated_at_us", "generated_at_us",
    "plaintext_bytes", "ciphertext_bytes", "envelope_bytes", "encryption_ns",
    "hashing_ns", "signing_ns",
}


def encoded(value):
    """Independent wire-format oracle, not the implementation under test."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def envelope(row):
    return {
        "schema": 1, "algorithm": "AES-256-GCM", "record_id": row["id"],
        "owner": row["owner"], "version": row["version"],
        "nonce_b64": row["nonce_b64"], "ciphertext_b64": row["ciphertext_b64"],
        "created_at_us": row["created_at_us"], "updated_at_us": row["updated_at_us"],
        "generated_at_us": row["generated_at_us"],
    }


def seal(keys, **changes):
    arguments = dict(record_id="record-1", owner="bob", version=1, title=TITLE,
                     body=BODY, created_at_us=1_234_000, saved_at_us=1_235_000)
    arguments.update(changes)
    return seal_record(keys, **arguments)


def resign(keys, row):
    """Reach decrypt/parse failure paths with otherwise valid envelope evidence."""
    data = encoded(envelope(row))
    row["sha256_hex"] = hashlib.sha256(data).hexdigest()
    row["signature_b64"] = base64.b64encode(keys.signing_key.sign(data)).decode("ascii")
    return row


def flip_b64(value):
    raw = bytearray(base64.b64decode(value, validate=True))
    raw[0] ^= 1
    return base64.b64encode(raw).decode("ascii")


def test_canonical_unicode_utf8():
    value = {"z": "🌍", "a": {"title": "Café", "body": "नमस्ते"}}
    assert canonical_bytes(value) == encoded(value)
    assert b"\\u" not in canonical_bytes(value)
    assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_round_trip_unicode(keys):
    row = seal(keys)
    assert set(row) == FIELDS
    before = dict(row)
    assert open_record(keys, row) == {"title": TITLE, "body": BODY}
    assert row == before
    assert row["updated_at_us"] == row["generated_at_us"] == 1_235_000
    assert row["created_at_us"] == 1_234_000
    nonce = base64.b64decode(row["nonce_b64"], validate=True)
    ciphertext = base64.b64decode(row["ciphertext_b64"], validate=True)
    signature = base64.b64decode(row["signature_b64"], validate=True)
    assert len(keys.aes_key) == 32 and len(nonce) == 12 and len(signature) == 64
    assert TITLE.encode("utf-8") not in ciphertext
    assert BODY.encode("utf-8") not in ciphertext
    aad = encoded({"record_id": "record-1", "owner": "bob", "version": 1})
    assert AESGCM(keys.aes_key).decrypt(nonce, ciphertext, aad) == encoded({"title": TITLE, "body": BODY})
    data = encoded(envelope(row))
    assert row["sha256_hex"] == hashlib.sha256(data).hexdigest()
    keys.signing_key.public_key().verify(signature, data)
    with pytest.raises(InvalidSignature):
        keys.signing_key.public_key().verify(signature, row["sha256_hex"].encode("ascii"))
    for name in ("encryption_ns", "hashing_ns", "signing_ns"):
        assert type(row[name]) is int and row[name] >= 0


def test_fresh_nonce(keys):
    first, second = seal(keys), seal(keys)
    assert first["nonce_b64"] != second["nonce_b64"]
    assert first["ciphertext_b64"] != second["ciphertext_b64"]
    assert open_record(keys, first) == open_record(keys, second)


@pytest.mark.parametrize("field", [
    "id", "owner", "version", "nonce_b64", "ciphertext_b64", "sha256_hex",
    "signature_b64", "created_at_us", "updated_at_us", "generated_at_us",
])
def test_tamper_rejected(keys, field):
    row = seal(keys)
    if field.endswith("_b64"):
        row[field] = flip_b64(row[field])
    elif field == "sha256_hex":
        row[field] = ("0" if row[field][0] != "0" else "1") + row[field][1:]
    elif isinstance(row[field], int):
        row[field] += 1
    else:
        row[field] += "-changed"
    with pytest.raises(IntegrityError) as caught:
        open_record(keys, row)
    assert TITLE not in str(caught.value) and BODY not in str(caught.value)


@pytest.mark.parametrize(("field", "value"), [
    ("nonce_b64", "!invalid!"), ("ciphertext_b64", "YWJj\n"),
    ("signature_b64", "!invalid!"), ("nonce_b64", base64.b64encode(b"short").decode()),
    ("ciphertext_b64", base64.b64encode(b"short").decode()),
    ("signature_b64", base64.b64encode(b"short").decode()),
    ("sha256_hex", "not-a-digest"), ("nonce_b64", None),
    ("version", "1"), ("version", True), ("version", 0),
    ("owner", None), ("id", 17), ("created_at_us", "1234000"),
    ("updated_at_us", 1.235), ("generated_at_us", None),
])
def test_bad_stored_formats_rejected(keys, field, value):
    row = seal(keys)
    row[field] = value
    # Repair hash/signature on malformed envelope fields: authentic evidence
    # does not make an invalid record representation acceptable.
    if field not in {"sha256_hex", "signature_b64"}:
        resign(keys, row)
    with pytest.raises(IntegrityError):
        open_record(keys, row)


def test_missing_fields_and_generic_failure(keys):
    row = seal(keys)
    failures = []
    for field in ("owner", "nonce_b64", "signature_b64", "sha256_hex", "created_at_us"):
        damaged = dict(row)
        del damaged[field]
        with pytest.raises(IntegrityError) as caught:
            open_record(keys, damaged)
        failures.append(str(caught.value))
    damaged = dict(row, signature_b64=flip_b64(row["signature_b64"]))
    with pytest.raises(IntegrityError) as caught:
        open_record(keys, damaged)
    failures.append(str(caught.value))
    assert len(set(failures)) == 1
    assert failures[0] and TITLE not in failures[0] and BODY not in failures[0]


def test_aes_authentication_failure_even_with_repaired_evidence(keys):
    row = seal(keys)
    row["owner"] = "alice"
    resign(keys, row)
    with pytest.raises(IntegrityError):
        open_record(keys, row)


@pytest.mark.parametrize("plaintext", [
    b"not JSON", b"\xff", b'[]', b'{"title":7,"body":"valid"}',
    b'{"title":"valid"}', b'{"title":"valid","body":null}',
])
def test_invalid_decrypted_plaintext_rejected(keys, plaintext):
    row = seal(keys)
    nonce = base64.b64decode(row["nonce_b64"])
    aad = encoded({"record_id": row["id"], "owner": row["owner"], "version": row["version"]})
    row["ciphertext_b64"] = base64.b64encode(AESGCM(keys.aes_key).encrypt(nonce, plaintext, aad)).decode("ascii")
    resign(keys, row)
    with pytest.raises(IntegrityError):
        open_record(keys, row)


def test_sqlite_row_support(keys):
    row = seal(keys)
    connection = sqlite3.connect(":memory:")
    try:
        connection.row_factory = sqlite3.Row
        query = "SELECT " + ", ".join("? AS " + name for name in row)
        stored = connection.execute(query, tuple(row.values())).fetchone()
        assert open_record(keys, stored) == {"title": TITLE, "body": BODY}
    finally:
        connection.close()


def test_exact_timer_scopes(keys, monkeypatch):
    events = []
    ticks = iter([100, 160, 200, 220, 300, 350])
    original_canonical = crypto.canonical_bytes
    original_aes = crypto.AESGCM
    original_hash = crypto.hashlib.sha256

    def clock():
        events.append("clock")
        return next(ticks)

    def serialize(value):
        kind = "envelope" if "schema" in value else "aad" if "record_id" in value else "plaintext"
        events.append("serialize:" + kind)
        return original_canonical(value)

    class ObservedAES:
        def __init__(self, key):
            events.append("aes:construct")
            self.actual = original_aes(key)

        def encrypt(self, nonce, data, aad):
            events.append("encrypt")
            return self.actual.encrypt(nonce, data, aad)

    class ObservedDigest:
        def __init__(self, data):
            events.append("hash")
            self.actual = original_hash(data)

        def digest(self):
            events.append("digest")
            return self.actual.digest()

        def hexdigest(self):
            events.append("hexdigest")
            return self.actual.hexdigest()

    class ObservedSigner:
        def sign(self, data):
            events.append("sign")
            return keys.signing_key.sign(data)

    monkeypatch.setattr(crypto, "canonical_bytes", serialize)
    monkeypatch.setattr(crypto, "AESGCM", ObservedAES)
    monkeypatch.setattr(crypto.hashlib, "sha256", ObservedDigest)
    observed_keys = replace(keys, signing_key=ObservedSigner())
    row = seal(observed_keys, clock=clock)
    assert (row["encryption_ns"], row["hashing_ns"], row["signing_ns"]) == (60, 20, 50)
    first_clock = events.index("clock")
    assert set(events[:first_clock]) == {"serialize:plaintext", "serialize:aad", "aes:construct"}
    assert events[first_clock:] == [
        "clock", "encrypt", "clock", "serialize:envelope", "clock",
        "hash", "digest", "clock", "clock", "sign", "clock",
    ]
    assert row["plaintext_bytes"] == len(encoded({"title": TITLE, "body": BODY}))
    assert row["ciphertext_bytes"] == row["plaintext_bytes"] + 16
    assert row["envelope_bytes"] == len(encoded(envelope(row)))
    with pytest.raises(StopIteration):
        next(ticks)


def test_open_does_not_regenerate_or_change_measurements(keys, monkeypatch):
    row = seal(keys, clock=iter([100, 160, 200, 220, 300, 350]).__next__)
    before = dict(row)

    def forbidden(*args, **kwargs):
        raise AssertionError("Opening must not generate new evidence or measurements")

    class VerifyOnlySigner:
        def public_key(self):
            return keys.signing_key.public_key()

        sign = forbidden

    monkeypatch.setattr(crypto, "seal_record", forbidden)
    monkeypatch.setattr(crypto, "perf_counter_ns", forbidden)
    verify_only = replace(keys, signing_key=VerifyOnlySigner())
    assert open_record(verify_only, row) == {"title": TITLE, "body": BODY}
    assert row == before


def test_verification_order_precedes_decryption(keys, monkeypatch):
    row = seal(keys)
    events = []
    original_aes = crypto.AESGCM

    class ObservedPublicKey:
        def verify(self, signature, data):
            events.append("verify")
            return keys.signing_key.public_key().verify(signature, data)

    class VerifyOnlySigner:
        def public_key(self):
            return ObservedPublicKey()

    class ObservedAES:
        def __init__(self, key):
            self.actual = original_aes(key)

        def decrypt(self, nonce, data, aad):
            events.append("decrypt")
            return self.actual.decrypt(nonce, data, aad)

    monkeypatch.setattr(crypto, "AESGCM", ObservedAES)
    verify_only = replace(keys, signing_key=VerifyOnlySigner())
    with pytest.raises(IntegrityError):
        open_record(verify_only, dict(row, sha256_hex="0" * 64))
    assert events == []
    with pytest.raises(IntegrityError):
        open_record(verify_only, dict(row, signature_b64=flip_b64(row["signature_b64"])))
    assert events == ["verify"]
    events.clear()
    assert open_record(verify_only, row) == {"title": TITLE, "body": BODY}
    assert events == ["verify", "decrypt"]

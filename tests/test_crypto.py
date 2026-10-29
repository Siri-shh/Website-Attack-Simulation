"""Public cryptographic contracts, including exact measured operation scopes."""

import base64
from dataclasses import replace
import hashlib
from io import BytesIO
import json
import os
import sqlite3

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image
import pytest

from security_lab import crypto
from security_lab.crypto import IntegrityError, canonical_bytes, open_record, seal_record


TITLE = "  Café — नमस्ते 🌍\n"
BODY = "秘密の本文\nLine two\t<keep & content>\n  "
FIELDS = {
    "id", "owner", "version", "nonce_b64", "ciphertext_b64", "sha256_hex",
    "signature_b64", "created_at_us", "updated_at_us", "generated_at_us",
    "plaintext_bytes", "ciphertext_bytes", "envelope_bytes", "encryption_ns",
    "hashing_ns", "signing_ns", "envelope_schema", "image_nonce",
    "image_ciphertext", "image_mime", "image_size", "image_plain_sha256",
    "image_cipher_sha256", "image_encrypt_ns", "image_hash_ns",
}
IMAGE_FIELDS = {
    "image_nonce", "image_ciphertext", "image_mime", "image_size",
    "image_plain_sha256", "image_cipher_sha256", "image_encrypt_ns",
    "image_hash_ns",
}
_png_buffer = BytesIO()
Image.new("RGB", (1, 1), (31, 97, 173)).save(_png_buffer, format="PNG")
PNG = _png_buffer.getvalue()


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


def v2_envelope(row):
    """Independent public wire-format oracle for a signed image row."""
    value = envelope(row)
    value["schema"] = 2
    value["image"] = {
        "nonce_b64": base64.b64encode(row["image_nonce"]).decode("ascii"),
        "mime": row["image_mime"],
        "plaintext_bytes": row["image_size"],
        "plaintext_sha256": row["image_plain_sha256"],
        "ciphertext_bytes": len(row["image_ciphertext"]),
        "ciphertext_sha256": row["image_cipher_sha256"],
    }
    return value


def seal(keys, **changes):
    """Build historical schema-1 evidence without calling the new v2 writer."""
    arguments = dict(record_id="record-1", owner="bob", version=1, title=TITLE,
                     body=BODY, created_at_us=1_234_000, saved_at_us=1_235_000)
    arguments.update(changes)
    arguments.pop("clock", None)
    plaintext = encoded({"title": arguments["title"], "body": arguments["body"]})
    nonce = os.urandom(12)
    aad = encoded({"record_id": arguments["record_id"],
                   "owner": arguments["owner"], "version": arguments["version"]})
    ciphertext = AESGCM(keys.aes_key).encrypt(nonce, plaintext, aad)
    row = {
        "id": arguments["record_id"], "owner": arguments["owner"],
        "version": arguments["version"],
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "created_at_us": arguments["created_at_us"],
        "updated_at_us": arguments["saved_at_us"],
        "generated_at_us": arguments["saved_at_us"],
    }
    data = encoded(envelope(row))
    row.update(sha256_hex=hashlib.sha256(data).hexdigest(),
               signature_b64=base64.b64encode(keys.signing_key.sign(data)).decode("ascii"),
               plaintext_bytes=len(plaintext), ciphertext_bytes=len(ciphertext),
               envelope_bytes=len(data), encryption_ns=1, hashing_ns=2, signing_ns=3,
               envelope_schema=1, **{field: None for field in IMAGE_FIELDS})
    return row


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


def test_v1_signed_wire_evidence_is_unchanged(keys, monkeypatch):
    monkeypatch.setattr(os, "urandom", lambda count: bytes(range(count)))
    row = seal(keys)
    data = encoded(envelope(row))
    assert row["envelope_schema"] == 1
    assert row["envelope_bytes"] == len(data)
    assert row["sha256_hex"] == hashlib.sha256(data).hexdigest()
    keys.signing_key.public_key().verify(
        base64.b64decode(row["signature_b64"]), data,
    )
    assert open_record(keys, row) == {"title": TITLE, "body": BODY}


def test_v2_default_no_image_and_measured_read(keys):
    from security_lab.crypto import open_record_image, open_record_measured

    row = seal_record(keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2)
    assert row["envelope_schema"] == 2
    assert all(row[field] is None for field in IMAGE_FIELDS)
    assert open_record(keys, row) == {"title": TITLE, "body": BODY}
    assert open_record_image(keys, row) is None
    text, image, measurements = open_record_measured(keys, row)
    assert text == {"title": TITLE, "body": BODY}
    assert image is None
    assert set(measurements) == {
        "hash_verification_ns", "signature_verification_ns",
        "text_decryption_ns", "image_decryption_ns",
    }
    assert measurements["image_decryption_ns"] is None
    assert all(type(measurements[name]) is int and measurements[name] >= 0
               for name in ("hash_verification_ns", "signature_verification_ns",
                            "text_decryption_ns"))


def test_v2_image_round_trip_has_separate_fresh_ciphertext(keys):
    from security_lab.crypto import open_record_image, open_record_measured

    first = seal_record(keys, record_id="record-2", owner="bob", version=1,
                        title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                        image_bytes=PNG, image_mime="image/png")
    second = seal_record(keys, record_id="record-2", owner="bob", version=1,
                         title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                         image_bytes=PNG, image_mime="image/png")
    assert first["envelope_schema"] == second["envelope_schema"] == 2
    assert all(first[field] is not None for field in IMAGE_FIELDS)
    assert isinstance(first["image_nonce"], bytes) and len(first["image_nonce"]) == 12
    assert isinstance(first["image_ciphertext"], bytes)
    assert PNG not in first["image_ciphertext"]
    assert first["image_nonce"] != second["image_nonce"]
    assert first["image_ciphertext"] != second["image_ciphertext"]
    assert open_record_image(keys, first) == ("image/png", PNG)
    assert open_record(keys, first) == {"title": TITLE, "body": BODY}
    text, image, measurements = open_record_measured(keys, first)
    assert text == {"title": TITLE, "body": BODY}
    assert image == PNG
    assert type(measurements["image_decryption_ns"]) is int
    assert measurements["image_decryption_ns"] >= 0


def test_v2_rejects_partially_present_image_evidence(keys):
    empty = seal_record(keys, record_id="record-2", owner="bob", version=1,
                        title=TITLE, body=BODY, created_at_us=1, saved_at_us=2)
    empty["image_size"] = 1
    with pytest.raises(IntegrityError):
        open_record(keys, empty)

    present = seal_record(keys, record_id="record-2", owner="bob", version=1,
                          title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                          image_bytes=PNG, image_mime="image/png")
    present["image_mime"] = None
    with pytest.raises(IntegrityError):
        open_record(keys, present)


@pytest.mark.parametrize("field", [
    "image_nonce", "image_ciphertext", "image_mime", "image_size",
    "image_plain_sha256", "image_cipher_sha256",
])
def test_v2_image_evidence_tampering_rejects_entire_record(keys, field):
    row = seal_record(keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                      image_bytes=PNG, image_mime="image/png")
    original = row[field]
    if isinstance(original, bytes):
        changed = bytearray(original)
        changed[-1] ^= 1  # includes the final GCM tag byte for ciphertext
        row[field] = bytes(changed)
    elif isinstance(original, int):
        row[field] = original + 1
    else:
        row[field] = ("image/jpeg" if field == "image_mime" else "0" * 64)
    with pytest.raises(IntegrityError):
        open_record(keys, row)
    from security_lab.crypto import open_record_image
    with pytest.raises(IntegrityError):
        open_record_image(keys, row)


@pytest.mark.parametrize("field", ["owner", "version"])
def test_v2_image_rejects_wrong_authenticated_identity(keys, field):
    from security_lab.crypto import open_record_image

    row = seal_record(keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                      image_bytes=PNG, image_mime="image/png")
    row[field] = "alice" if field == "owner" else 2
    with pytest.raises(IntegrityError):
        open_record_image(keys, row)


@pytest.mark.parametrize(("field", "replacement"), [
    ("owner", "alice"), ("version", 2),
])
def test_v2_image_gcm_aad_rejects_rebound_signed_identity(keys, field, replacement):
    from security_lab.crypto import open_record_image

    row = seal_record(keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                      image_bytes=PNG, image_mime="image/png")
    original_image_aad = encoded({
        "purpose": "record-image", "record_id": row["id"],
        "owner": row["owner"], "version": row["version"],
        "mime": row["image_mime"], "size": row["image_size"],
    })
    assert AESGCM(keys.aes_key).decrypt(
        row["image_nonce"], row["image_ciphertext"], original_image_aad,
    ) == PNG

    row[field] = replacement
    text_aad = encoded({"record_id": row["id"], "owner": row["owner"],
                        "version": row["version"]})
    text_nonce = os.urandom(12)
    text_ciphertext = AESGCM(keys.aes_key).encrypt(
        text_nonce, encoded({"title": TITLE, "body": BODY}), text_aad,
    )
    row["nonce_b64"] = base64.b64encode(text_nonce).decode("ascii")
    row["ciphertext_b64"] = base64.b64encode(text_ciphertext).decode("ascii")
    signed_bytes = encoded(v2_envelope(row))
    row["sha256_hex"] = hashlib.sha256(signed_bytes).hexdigest()
    row["signature_b64"] = base64.b64encode(
        keys.signing_key.sign(signed_bytes)
    ).decode("ascii")
    row["envelope_bytes"] = len(signed_bytes)
    keys.signing_key.public_key().verify(
        base64.b64decode(row["signature_b64"]), signed_bytes,
    )
    assert AESGCM(keys.aes_key).decrypt(text_nonce, text_ciphertext, text_aad) == encoded(
        {"title": TITLE, "body": BODY}
    )
    rebound_image_aad = encoded({
        "purpose": "record-image", "record_id": row["id"],
        "owner": row["owner"], "version": row["version"],
        "mime": row["image_mime"], "size": row["image_size"],
    })
    with pytest.raises(InvalidTag):
        AESGCM(keys.aes_key).decrypt(
            row["image_nonce"], row["image_ciphertext"], rebound_image_aad,
        )
    with pytest.raises(IntegrityError):
        open_record_image(keys, row)


def test_v2_image_seal_timers_cover_only_crypto_calls(keys, monkeypatch):
    events = []
    ticks = iter([100, 160, 200, 270, 300, 311, 400, 413, 500, 517, 600, 619])
    original_canonical = crypto.canonical_bytes
    original_aes = crypto.AESGCM
    original_sha = crypto.hashlib.sha256
    image_ciphertext = []

    def clock():
        events.append("clock")
        return next(ticks)

    def serialize(value):
        if "schema" in value:
            kind = "envelope"
        elif "purpose" in value:
            kind = "image_aad"
        elif "record_id" in value:
            kind = "text_aad"
        else:
            kind = "text"
        events.append("serialize:" + kind)
        return original_canonical(value)

    class ObservedAES:
        def __init__(self, key):
            events.append("aes:construct")
            self.actual = original_aes(key)

        def encrypt(self, nonce, data, aad):
            kind = "image" if data == PNG else "text"
            events.append("encrypt:" + kind)
            result = self.actual.encrypt(nonce, data, aad)
            if kind == "image":
                image_ciphertext.append(result)
            return result

    class ObservedDigest:
        def __init__(self, data):
            if data == PNG:
                kind = "image_plain"
            elif image_ciphertext and data == image_ciphertext[0]:
                kind = "image_cipher"
            else:
                kind = "envelope"
            events.append("hash:" + kind)
            self.actual = original_sha(data)

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
    row = seal_record(observed_keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                      image_bytes=PNG, image_mime="image/png", clock=clock)
    assert (row["encryption_ns"], row["image_encrypt_ns"], row["image_hash_ns"],
            row["hashing_ns"], row["signing_ns"]) == (60, 70, 24, 17, 19)
    assert events == [
        "serialize:text", "serialize:text_aad", "aes:construct",
        "clock", "encrypt:text", "clock",
        "serialize:image_aad", "clock", "encrypt:image", "clock",
        "clock", "hash:image_plain", "hexdigest", "clock",
        "clock", "hash:image_cipher", "hexdigest", "clock",
        "serialize:envelope", "clock", "hash:envelope", "digest", "clock",
        "clock", "sign", "clock",
    ]
    with pytest.raises(StopIteration):
        next(ticks)


def test_measured_v1_read_times_only_crypto_operations(keys, monkeypatch):
    from security_lab.crypto import open_record_measured

    row = seal(keys)
    before = dict(row)
    elapsed = [100]
    original_sha = crypto.hashlib.sha256
    original_aes = crypto.AESGCM

    class TimedHash:
        def __init__(self, data):
            self.actual = original_sha(data)

        def digest(self):
            elapsed[0] += 7
            return self.actual.digest()

        def hexdigest(self):
            elapsed[0] += 7
            return self.actual.hexdigest()

    class TimedPublicKey:
        def verify(self, signature, data):
            elapsed[0] += 11
            return keys.signing_key.public_key().verify(signature, data)

    class VerifyOnlySigner:
        def public_key(self):
            return TimedPublicKey()

    class TimedAES:
        def __init__(self, key):
            self.actual = original_aes(key)

        def decrypt(self, nonce, data, aad):
            elapsed[0] += 13
            return self.actual.decrypt(nonce, data, aad)

    monkeypatch.setattr(crypto, "perf_counter_ns", lambda: elapsed[0])
    monkeypatch.setattr(crypto.hashlib, "sha256", TimedHash)
    monkeypatch.setattr(crypto, "AESGCM", TimedAES)
    measured_keys = replace(keys, signing_key=VerifyOnlySigner())
    text, image, times = open_record_measured(measured_keys, row)
    assert text == {"title": TITLE, "body": BODY}
    assert image is None
    assert times == {
        "hash_verification_ns": 7,
        "signature_verification_ns": 11,
        "text_decryption_ns": 13,
        "image_decryption_ns": None,
    }
    assert row == before


def test_measured_v2_image_read_excludes_aad_serialization(keys, monkeypatch):
    from security_lab.crypto import open_record_measured

    row = seal_record(keys, record_id="record-2", owner="bob", version=1,
                      title=TITLE, body=BODY, created_at_us=1, saved_at_us=2,
                      image_bytes=PNG, image_mime="image/png")
    before = dict(row)
    elapsed = [100]
    original_canonical = crypto.canonical_bytes
    original_sha = crypto.hashlib.sha256
    original_aes = crypto.AESGCM

    def serialize(value):
        if "purpose" in value:
            elapsed[0] += 101  # Parsing/serialization is outside decrypt timing.
        return original_canonical(value)

    class TimedHash:
        def __init__(self, data):
            self.actual = original_sha(data)

        def digest(self):
            elapsed[0] += 7
            return self.actual.digest()

        def hexdigest(self):
            elapsed[0] += 7
            return self.actual.hexdigest()

    class TimedPublicKey:
        def verify(self, signature, data):
            elapsed[0] += 11
            return keys.signing_key.public_key().verify(signature, data)

    class VerifyOnlySigner:
        def public_key(self):
            return TimedPublicKey()

    class TimedAES:
        def __init__(self, key):
            self.actual = original_aes(key)

        def decrypt(self, nonce, data, aad):
            elapsed[0] += 17 if nonce == row["image_nonce"] else 13
            return self.actual.decrypt(nonce, data, aad)

    monkeypatch.setattr(crypto, "canonical_bytes", serialize)
    monkeypatch.setattr(crypto, "perf_counter_ns", lambda: elapsed[0])
    monkeypatch.setattr(crypto.hashlib, "sha256", TimedHash)
    monkeypatch.setattr(crypto, "AESGCM", TimedAES)
    measured_keys = replace(keys, signing_key=VerifyOnlySigner())
    text, image, times = open_record_measured(measured_keys, row)
    assert text == {"title": TITLE, "body": BODY}
    assert image == PNG
    assert times == {
        "hash_verification_ns": 21,
        "signature_verification_ns": 11,
        "text_decryption_ns": 13,
        "image_decryption_ns": 17,
    }
    assert row == before


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

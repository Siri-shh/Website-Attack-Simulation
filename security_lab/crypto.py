"""Versioned record cryptography and saved generation measurements.

Read measurements are transient and never change the signed evidence.
"""

import base64
import binascii
from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import os
from time import perf_counter_ns
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .identity import KeyRing
from .images import MAX_IMAGE_BYTES, validate_image_upload


class IntegrityError(Exception):
    """A stored record failed integrity or format verification."""


_IMAGE_FIELDS = (
    "image_nonce", "image_ciphertext", "image_mime", "image_size",
    "image_plain_sha256", "image_cipher_sha256", "image_encrypt_ns",
    "image_hash_ns",
)


def canonical_bytes(value: dict) -> bytes:
    """Serialize the shared wire representation without altering Unicode text."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _validate_metadata(record_id, owner, version, created_at_us, updated_at_us, generated_at_us):
    if not isinstance(record_id, str) or not isinstance(owner, str):
        raise ValueError("Invalid record identity")
    # bool is an int subclass, but is not a record version or timestamp.
    if type(version) is not int or version < 1:
        raise ValueError("Invalid record version")
    if any(type(value) is not int for value in (created_at_us, updated_at_us, generated_at_us)):
        raise ValueError("Invalid record timestamp")


def _envelope(row) -> dict:
    """Read by key so sqlite3.Row and ordinary mappings share the same path."""
    record_id, owner, version = row["id"], row["owner"], row["version"]
    created, updated, generated = (
        row["created_at_us"], row["updated_at_us"], row["generated_at_us"]
    )
    _validate_metadata(record_id, owner, version, created, updated, generated)
    return {
        "schema": 1,
        "algorithm": "AES-256-GCM",
        "record_id": record_id,
        "owner": owner,
        "version": version,
        "nonce_b64": row["nonce_b64"],
        "ciphertext_b64": row["ciphertext_b64"],
        "created_at_us": created,
        "updated_at_us": updated,
        "generated_at_us": generated,
    }


def _base64_text(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode_base64(value) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Invalid Base64 field")
    raw = base64.b64decode(value, validate=True)
    if _base64_text(raw) != value:
        raise ValueError("Noncanonical Base64 field")
    return raw


def _optional_field(row, name):
    try:
        return row[name]
    except (KeyError, IndexError):
        return None


def _sha256_hex(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _image_descriptor(row, schema: int) -> dict | None:
    values = [_optional_field(row, field) for field in _IMAGE_FIELDS]
    if schema == 1:
        if any(value is not None for value in values):
            raise ValueError("V1 records cannot contain image evidence")
        return None
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError("Incomplete image evidence")
    nonce, ciphertext, mime, size, plain_hash, cipher_hash, encrypt_ns, hash_ns = values
    if type(nonce) is not bytes or len(nonce) != 12:
        raise ValueError("Invalid image nonce")
    if type(ciphertext) is not bytes or not 16 <= len(ciphertext) <= MAX_IMAGE_BYTES + 16:
        raise ValueError("Invalid image ciphertext")
    if mime not in ("image/png", "image/jpeg"):
        raise ValueError("Invalid image MIME")
    if type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES or len(ciphertext) != size + 16:
        raise ValueError("Invalid image size")
    if not _sha256_hex(plain_hash) or not _sha256_hex(cipher_hash):
        raise ValueError("Invalid image SHA-256")
    if any(type(value) is not int or value < 0 for value in (encrypt_ns, hash_ns)):
        raise ValueError("Invalid image measurements")
    return {
        "nonce_b64": _base64_text(nonce), "mime": mime,
        "plaintext_bytes": size, "plaintext_sha256": plain_hash,
        "ciphertext_bytes": len(ciphertext), "ciphertext_sha256": cipher_hash,
    }


def _v2_envelope(row, descriptor: dict | None) -> dict:
    value = _envelope(row)
    value["schema"] = 2
    value["image"] = descriptor
    return value


def _image_aad(row) -> bytes:
    return canonical_bytes({
        "purpose": "record-image", "record_id": row["id"],
        "owner": row["owner"], "version": row["version"],
        "mime": row["image_mime"], "size": row["image_size"],
    })


def seal_record(
    keys: KeyRing, *, record_id: str, owner: str, version: int,
    title: str, body: str, created_at_us: int, saved_at_us: int,
    image_bytes: bytes | None = None, image_mime: str | None = None,
    clock: Callable[[], int] = perf_counter_ns,
) -> dict:
    """Seal text and an optional image in a schema-2 signed envelope."""
    _validate_metadata(record_id, owner, version, created_at_us, saved_at_us, saved_at_us)
    if not isinstance(title, str) or not isinstance(body, str):
        raise ValueError("Record title and body must be strings")
    if len(keys.aes_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if (image_bytes is None) != (image_mime is None):
        raise ValueError("Image bytes and MIME must be supplied together")
    if image_bytes is not None:
        image_bytes, image_mime = validate_image_upload(image_bytes, image_mime)

    plaintext = canonical_bytes({"title": title, "body": body})
    aad = canonical_bytes({"record_id": record_id, "owner": owner, "version": version})
    nonce = os.urandom(12)
    aes = AESGCM(keys.aes_key)

    started = clock()
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    finished = clock()
    encryption_ns = finished - started

    row = {
        "id": record_id,
        "owner": owner,
        "version": version,
        "nonce_b64": _base64_text(nonce),
        "ciphertext_b64": _base64_text(ciphertext),
        "created_at_us": created_at_us,
        "updated_at_us": saved_at_us,
        "generated_at_us": saved_at_us,
        "envelope_schema": 2,
        **{field: None for field in _IMAGE_FIELDS},
    }
    if image_bytes is not None:
        image_nonce = os.urandom(12)
        if image_nonce == nonce:
            image_nonce = image_nonce[:-1] + bytes((image_nonce[-1] ^ 1,))
        row.update(image_nonce=image_nonce, image_mime=image_mime,
                   image_size=len(image_bytes))
        image_aad = _image_aad(row)
        started = clock()
        image_ciphertext = aes.encrypt(image_nonce, image_bytes, image_aad)
        image_encrypt_ns = clock() - started
        started = clock()
        plain_hash = hashlib.sha256(image_bytes).hexdigest()
        plain_hash_ns = clock() - started
        started = clock()
        cipher_hash = hashlib.sha256(image_ciphertext).hexdigest()
        cipher_hash_ns = clock() - started
        row.update(
            image_ciphertext=image_ciphertext,
            image_plain_sha256=plain_hash,
            image_cipher_sha256=cipher_hash,
            image_encrypt_ns=image_encrypt_ns,
            image_hash_ns=plain_hash_ns + cipher_hash_ns,
        )
    envelope = canonical_bytes(_v2_envelope(row, _image_descriptor(row, 2)))

    started = clock()
    digest = hashlib.sha256(envelope).digest()
    finished = clock()
    hashing_ns = finished - started

    started = clock()
    signature = keys.signing_key.sign(envelope)
    finished = clock()
    signing_ns = finished - started

    row.update(
        sha256_hex=digest.hex(),
        signature_b64=_base64_text(signature),
        plaintext_bytes=len(plaintext),
        ciphertext_bytes=len(ciphertext),
        envelope_bytes=len(envelope),
        encryption_ns=encryption_ns,
        hashing_ns=hashing_ns,
        signing_ns=signing_ns,
    )
    return row


def _open_record(keys: KeyRing, row: Mapping[str, Any], *, measured: bool):
    """Verify all stored evidence before returning any plaintext to a caller."""
    try:
        schema = _optional_field(row, "envelope_schema")
        if schema is None:
            schema = 1  # Pre-migration mappings have no discriminator field.
        if type(schema) is not int or schema not in (1, 2):
            raise ValueError("Invalid envelope schema")
        descriptor = _image_descriptor(row, schema)
        envelope = canonical_bytes(
            _envelope(row) if schema == 1 else _v2_envelope(row, descriptor)
        )
        nonce = _decode_base64(row["nonce_b64"])
        ciphertext = _decode_base64(row["ciphertext_b64"])
        signature = _decode_base64(row["signature_b64"])
        if len(nonce) != 12 or len(ciphertext) < 16 or len(signature) != 64:
            raise ValueError("Invalid cryptographic field length")
        digest_hex = row["sha256_hex"]
        if not isinstance(digest_hex, str) or len(digest_hex) != 64:
            raise ValueError("Invalid SHA-256 field")
        saved_digest = bytes.fromhex(digest_hex)
        hash_ns = 0
        started = perf_counter_ns() if measured else 0
        calculated_digest = hashlib.sha256(envelope).digest()
        if measured:
            hash_ns += perf_counter_ns() - started
        if len(saved_digest) != 32 or not hmac.compare_digest(saved_digest, calculated_digest):
            raise ValueError("Envelope hash mismatch")
        started = perf_counter_ns() if measured else 0
        keys.signing_key.public_key().verify(signature, envelope)
        signature_ns = perf_counter_ns() - started if measured else None

        if len(keys.aes_key) != 32:
            raise ValueError("Invalid AES-256 key")
        if descriptor is not None:
            started = perf_counter_ns() if measured else 0
            actual_cipher_hash = hashlib.sha256(row["image_ciphertext"]).hexdigest()
            if measured:
                hash_ns += perf_counter_ns() - started
            if not hmac.compare_digest(actual_cipher_hash, row["image_cipher_sha256"]):
                raise ValueError("Image ciphertext hash mismatch")
        aad = canonical_bytes({
            "record_id": row["id"], "owner": row["owner"], "version": row["version"]
        })
        aes = AESGCM(keys.aes_key)
        started = perf_counter_ns() if measured else 0
        plaintext = aes.decrypt(nonce, ciphertext, aad)
        text_ns = perf_counter_ns() - started if measured else None
        value = json.loads(plaintext.decode("utf-8"))
        if (
            not isinstance(value, dict) or set(value) != {"title", "body"}
            or not isinstance(value["title"], str)
            or not isinstance(value["body"], str)
        ):
            raise ValueError("Invalid plaintext shape")

        image = None
        image_ns = None
        if descriptor is not None:
            image_aad = _image_aad(row)
            started = perf_counter_ns() if measured else 0
            image = aes.decrypt(row["image_nonce"], row["image_ciphertext"], image_aad)
            image_ns = perf_counter_ns() - started if measured else None
            if len(image) != row["image_size"]:
                raise ValueError("Image plaintext size mismatch")
            started = perf_counter_ns() if measured else 0
            actual_plain_hash = hashlib.sha256(image).hexdigest()
            if measured:
                hash_ns += perf_counter_ns() - started
            if not hmac.compare_digest(actual_plain_hash, row["image_plain_sha256"]):
                raise ValueError("Image plaintext hash mismatch")

        times = {
            "hash_verification_ns": hash_ns if measured else None,
            "signature_verification_ns": signature_ns,
            "text_decryption_ns": text_ns,
            "image_decryption_ns": image_ns,
        }
        return ({"title": value["title"], "body": value["body"]}, image,
                row["image_mime"] if image is not None else None, times)
    except (
        KeyError, IndexError, TypeError, ValueError, UnicodeError,
        binascii.Error, InvalidSignature, InvalidTag, OverflowError, RecursionError,
    ):
        raise IntegrityError("Record integrity verification failed") from None


def open_record(keys: KeyRing, row: Mapping[str, Any]) -> dict[str, str]:
    """Verify all v1/v2 evidence before releasing text."""
    text, _image, _mime, _times = _open_record(keys, row, measured=False)
    return text


def open_record_image(keys: KeyRing, row: Mapping[str, Any]) -> tuple[str, bytes] | None:
    """Verify the entire record before releasing its optional original image."""
    _text, image, mime, _times = _open_record(keys, row, measured=False)
    return (mime, image) if image is not None else None


def open_record_measured(
    keys: KeyRing, row: Mapping[str, Any]
) -> tuple[dict[str, str], bytes | None, dict[str, int | None]]:
    """Return verified content and transient operation-only read durations."""
    text, image, _mime, times = _open_record(keys, row, measured=True)
    return text, image, times

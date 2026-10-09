"""Canonical record cryptography and saved operation measurements.

The persisted durations describe three individual operations on this machine.
Opening a record verifies saved evidence; it never regenerates observations.
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


class IntegrityError(Exception):
    """A stored record failed integrity or format verification."""


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


def seal_record(
    keys: KeyRing, *, record_id: str, owner: str, version: int,
    title: str, body: str, created_at_us: int, saved_at_us: int,
    clock: Callable[[], int] = perf_counter_ns,
) -> dict:
    """Encrypt once, hash/sign the exact envelope, and save actual deltas."""
    _validate_metadata(record_id, owner, version, created_at_us, saved_at_us, saved_at_us)
    if not isinstance(title, str) or not isinstance(body, str):
        raise ValueError("Record title and body must be strings")
    if len(keys.aes_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")

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
    }
    envelope = canonical_bytes(_envelope(row))

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


def open_record(keys: KeyRing, row: Mapping[str, Any]) -> dict[str, str]:
    """Verify format, hash and signature before decrypting; release no partial text."""
    try:
        envelope = canonical_bytes(_envelope(row))
        nonce = _decode_base64(row["nonce_b64"])
        ciphertext = _decode_base64(row["ciphertext_b64"])
        signature = _decode_base64(row["signature_b64"])
        if len(nonce) != 12 or len(ciphertext) < 16 or len(signature) != 64:
            raise ValueError("Invalid cryptographic field length")
        digest_hex = row["sha256_hex"]
        if not isinstance(digest_hex, str) or len(digest_hex) != 64:
            raise ValueError("Invalid SHA-256 field")
        saved_digest = bytes.fromhex(digest_hex)
        if len(saved_digest) != 32 or not hmac.compare_digest(
            saved_digest, hashlib.sha256(envelope).digest()
        ):
            raise ValueError("Envelope hash mismatch")
        keys.signing_key.public_key().verify(signature, envelope)

        if len(keys.aes_key) != 32:
            raise ValueError("Invalid AES-256 key")
        aad = canonical_bytes({
            "record_id": row["id"], "owner": row["owner"], "version": row["version"]
        })
        plaintext = AESGCM(keys.aes_key).decrypt(nonce, ciphertext, aad)
        value = json.loads(plaintext.decode("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"title", "body"}
            or not isinstance(value["title"], str)
            or not isinstance(value["body"], str)
        ):
            raise ValueError("Invalid plaintext shape")
        return {"title": value["title"], "body": value["body"]}
    except (
        KeyError, IndexError, TypeError, ValueError, UnicodeError,
        binascii.Error, InvalidSignature, InvalidTag, OverflowError, RecursionError,
    ):
        # Neither parser/cryptographic exceptions nor partial plaintext escape.
        raise IntegrityError("Record integrity verification failed") from None

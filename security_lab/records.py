"""Atomic, ownership-checked services for the latest encrypted records."""

from uuid import uuid4

from .audit import append_app_event
from .config import Config, utc_us
from .crypto import IntegrityError, open_record, seal_record
from .db import transaction
from .identity import KeyRing


_RECORD_FIELDS = (
    "id", "owner", "version", "nonce_b64", "ciphertext_b64", "sha256_hex",
    "signature_b64", "created_at_us", "updated_at_us", "generated_at_us",
    "plaintext_bytes", "ciphertext_bytes", "envelope_bytes", "encryption_ns",
    "hashing_ns", "signing_ns",
)


def insert_record_version(conn, row):
    """Append a complete immutable snapshot of a current record row."""
    conn.execute(
        "INSERT INTO record_versions (" + ", ".join(_RECORD_FIELDS) + ") VALUES (" +
        ", ".join("?" for _ in _RECORD_FIELDS) + ")",
        tuple(row[field] for field in _RECORD_FIELDS),
    )


class RecordMissing(Exception):
    """The requested record does not exist."""


class RecordDenied(Exception):
    """The requested record belongs to another user."""


def _event(conn, config, keys, *, kind, owner, record_id, src_ip, session_ref, time_us=None):
    """Keep the signed allowlist free of submitted or decrypted content."""
    append_app_event(conn, keys, {
        "domain": "live",
        "event_id": uuid4().hex,
        "time_us": utc_us() if time_us is None else time_us,
        "kind": kind,
        "src_ip": src_ip,
        "dst_ip": config.server_ip,
        "dst_port": config.storage_port,
        "username": owner,
        "session_ref": session_ref,
        "record_id": record_id,
        "outcome": kind,
    })


def _checked_record(conn, config, keys, *, owner, record_id, src_ip, session_ref):
    """Return expected failures so their audit transaction can commit first."""
    found = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
    if found is None:
        return None, None, RecordMissing("Record not found")
    row = dict(found)
    if row["owner"] != owner:
        _event(
            conn, config, keys, kind="foreign_record_denied", owner=owner,
            record_id=record_id, src_ip=src_ip, session_ref=session_ref,
        )
        return None, None, RecordDenied("Record access denied")
    try:
        plaintext = open_record(keys, row)
    except IntegrityError:
        _event(
            conn, config, keys, kind="integrity_failure", owner=owner,
            record_id=record_id, src_ip=src_ip, session_ref=session_ref,
        )
        return None, None, IntegrityError("Record integrity verification failed")
    return row, plaintext, None


def save_record(
    config: Config, keys: KeyRing, *, owner: str, record_id: str | None,
    title: str, body: str, src_ip: str, session_ref: str,
) -> dict:
    """Seal and audit the latest version together under an immediate lock."""
    for label, value, maximum in (("Title", title, 120), ("Body", body, 10_000)):
        if not isinstance(value, str) or not 1 <= len(value) <= maximum or not value.strip():
            raise ValueError(f"{label} must contain 1 to {maximum} characters and non-whitespace text")

    error = None
    with transaction(config) as conn:
        previous = None
        if record_id is not None:
            previous, _, error = _checked_record(
                conn, config, keys, owner=owner, record_id=record_id,
                src_ip=src_ip, session_ref=session_ref,
            )
        if error is None:
            saved_at = utc_us()
            row = seal_record(
                keys, record_id=uuid4().hex if record_id is None else record_id,
                owner=owner, version=1 if previous is None else previous["version"] + 1,
                title=title, body=body,
                created_at_us=saved_at if previous is None else previous["created_at_us"],
                saved_at_us=saved_at,
            )
            if previous is None:
                conn.execute(
                    f"INSERT INTO records ({','.join(_RECORD_FIELDS)}) "
                    f"VALUES ({','.join('?' for _ in _RECORD_FIELDS)})",
                    tuple(row[field] for field in _RECORD_FIELDS),
                )
            else:
                conn.execute(
                    "UPDATE records SET " + ",".join(f"{field}=?" for field in _RECORD_FIELDS[1:])
                    + " WHERE id=?",
                    tuple(row[field] for field in _RECORD_FIELDS[1:]) + (row["id"],),
                )
            insert_record_version(conn, row)
            _event(
                conn, config, keys,
                kind="record_created" if previous is None else "record_updated",
                owner=owner, record_id=row["id"], src_ip=src_ip,
                session_ref=session_ref, time_us=saved_at,
            )
    # Raising inside transaction() would roll back denied/integrity evidence.
    if error is not None:
        raise error from None
    return row


def list_records(
    config: Config, keys: KeyRing, *, owner: str, src_ip: str, session_ref: str,
) -> list[dict]:
    """Return summaries only after every selected owned record verifies."""
    summaries = []
    error = None
    with transaction(config) as conn:
        rows = conn.execute(
            "SELECT * FROM records WHERE owner=? ORDER BY updated_at_us DESC,id",
            (owner,),
        ).fetchall()
        for row in rows:
            try:
                plaintext = open_record(keys, row)
            except IntegrityError:
                _event(
                    conn, config, keys, kind="integrity_failure", owner=owner,
                    record_id=row["id"], src_ip=src_ip, session_ref=session_ref,
                )
                error = IntegrityError("Record integrity verification failed")
                break
            summaries.append({
                "id": row["id"], "title": plaintext["title"], "version": row["version"],
                "created_at_us": row["created_at_us"], "updated_at_us": row["updated_at_us"],
            })
    if error is not None:
        raise error from None
    return summaries


def read_record(
    config: Config, keys: KeyRing, *, owner: str, record_id: str,
    src_ip: str, session_ref: str,
) -> tuple[dict, dict]:
    """Check ownership and integrity before returning evidence or plaintext."""
    with transaction(config) as conn:
        row, plaintext, error = _checked_record(
            conn, config, keys, owner=owner, record_id=record_id,
            src_ip=src_ip, session_ref=session_ref,
        )
        if error is None:
            _event(
                conn, config, keys, kind="record_read", owner=owner,
                record_id=record_id, src_ip=src_ip, session_ref=session_ref,
            )
    if error is not None:
        raise error from None
    return row, plaintext


def read_record_history(config: Config, keys: KeyRing, *, owner: str, record_id: str,
                        src_ip: str, session_ref: str) -> list[tuple[dict, dict]]:
    """Return all verified snapshots newest first, or fail without partial plaintext."""
    error = None
    verified = []
    with transaction(config) as conn:
        current, _current_plaintext, error = _checked_record(
            conn, config, keys, owner=owner, record_id=record_id,
            src_ip=src_ip, session_ref=session_ref,
        )
        if error is None:
            snapshots = [dict(row) for row in conn.execute(
                "SELECT * FROM record_versions WHERE id=? ORDER BY version DESC",
                (record_id,),
            ).fetchall()]
            integrity_problem = not snapshots
            if snapshots:
                integrity_problem = (
                    any(row["id"] != record_id or row["owner"] != owner for row in snapshots)
                    or any(
                        snapshots[index]["version"] != snapshots[index + 1]["version"] + 1
                        for index in range(len(snapshots) - 1)
                    )
                    or any(current[field] != snapshots[0][field] for field in _RECORD_FIELDS)
                )
            if integrity_problem:
                error = IntegrityError("Record history integrity verification failed")
            else:
                try:
                    verified = [(row, open_record(keys, row)) for row in snapshots]
                except IntegrityError:
                    error = IntegrityError("Record history integrity verification failed")
            if error is not None:
                _event(conn, config, keys, kind="integrity_failure", owner=owner,
                       record_id=record_id, src_ip=src_ip, session_ref=session_ref)
            else:
                _event(conn, config, keys, kind="record_read", owner=owner,
                       record_id=record_id, src_ip=src_ip, session_ref=session_ref)
    if error is not None:
        raise error from None
    return verified

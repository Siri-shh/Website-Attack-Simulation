"""Record service contracts exercised against real SQLite and cryptography."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from io import BytesIO
import json
from threading import Barrier
from uuid import UUID

import pytest
from PIL import Image
from werkzeug.security import generate_password_hash

from security_lab import records
from security_lab.audit import verify_app_event
from security_lab.crypto import IntegrityError, open_record, open_record_image
from security_lab.db import connect, transaction


@pytest.fixture
def seeded(config, keys):
    password_hash = generate_password_hash("test-password", method="scrypt")
    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES (?,?,?,?)",
            [(name, "user", password_hash, 1) for name in ("alice", "bob")],
        )
    return config, keys


def save(seeded, *, owner="alice", record_id=None, title="Private title", body="Private body",
         image_action="keep", image_bytes=None, image_mime=None):
    config, keys = seeded
    image_options = {}
    if image_action != "keep" or image_bytes is not None or image_mime is not None:
        image_options = {
            "image_action": image_action, "image_bytes": image_bytes, "image_mime": image_mime,
        }
    return records.save_record(
        config, keys, owner=owner, record_id=record_id, title=title, body=body,
        src_ip="192.0.2.10", session_ref="test-session",
        **image_options,
    )


def tiny_image(image_format="PNG"):
    buffer = BytesIO()
    Image.new("RGB", (2, 2), (14, 28, 42)).save(buffer, format=image_format)
    return buffer.getvalue()


def stored_rows(config, table):
    # The table argument is only one of the literals below, never user input.
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def assert_signed_event(keys, event, *, kind, owner, record_id):
    assert verify_app_event(keys, event)
    assert event["kind"] == kind
    assert event["username"] == owner
    assert event["record_id"] == record_id
    assert event["src_ip"] == "192.0.2.10"
    assert event["session_ref"] == "test-session"
    assert set(json.loads(event["payload_json"])) == {
        "domain", "event_id", "time_us", "kind", "src_ip", "dst_ip", "dst_port",
        "username", "session_ref", "record_id", "outcome",
    }


def test_create_then_edit_keeps_signed_snapshots_and_saved_timestamps(seeded, monkeypatch):
    config, keys = seeded
    monkeypatch.setattr(records, "utc_us", lambda: 1_000_000)
    first = save(seeded, title="  Private title é  ", body="\nPrivate body\n")
    assert UUID(first["id"]).hex == first["id"]
    assert first["owner"] == "alice"
    assert first["version"] == 1
    assert first["created_at_us"] == first["updated_at_us"] == first["generated_at_us"] == 1_000_000
    assert open_record(keys, first) == {"title": "  Private title é  ", "body": "\nPrivate body\n"}

    monkeypatch.setattr(records, "utc_us", lambda: 2_000_000)
    second = save(seeded, record_id=first["id"], title="Edited title", body="Edited body")
    assert second["id"] == first["id"]
    assert second["version"] == 2
    assert second["created_at_us"] == 1_000_000
    assert second["updated_at_us"] == second["generated_at_us"] == 2_000_000
    assert second["nonce_b64"] != first["nonce_b64"]
    assert second["ciphertext_b64"] != first["ciphertext_b64"]
    assert second["sha256_hex"] != first["sha256_hex"]
    assert second["signature_b64"] != first["signature_b64"]
    assert stored_rows(config, "records") == [second]
    versions = stored_rows(config, "record_versions")
    assert [(row["id"], row["version"]) for row in versions] == [(first["id"], 1), (first["id"], 2)]
    for snapshot, expected in zip(versions, (first, second)):
        assert snapshot["id"] == expected["id"]
        assert snapshot["owner"] == expected["owner"]
        assert snapshot["ciphertext_b64"] == expected["ciphertext_b64"]
        assert snapshot["nonce_b64"] == expected["nonce_b64"]
        assert snapshot["sha256_hex"] == expected["sha256_hex"]
        assert snapshot["signature_b64"] == expected["signature_b64"]
        assert snapshot["created_at_us"] == expected["created_at_us"]
        assert snapshot["updated_at_us"] == expected["updated_at_us"]
        assert snapshot["generated_at_us"] == expected["generated_at_us"]
        assert open_record(keys, snapshot) == open_record(keys, expected)
        for timing in ("encryption_ns", "hashing_ns", "signing_ns"):
            assert snapshot[timing] == expected[timing]
    history = records.read_record_history(
        config, keys, owner="alice", record_id=first["id"],
        src_ip="192.0.2.10", session_ref="test-session",
    )
    assert [row["version"] for row, _ in history] == [2, 1]
    assert [plaintext["body"] for _, plaintext in history] == ["Edited body", "\nPrivate body\n"]
    assert open_record(keys, second) == {"title": "Edited title", "body": "Edited body"}
    events = stored_rows(config, "events")
    assert len(events) == 3
    for event, kind, time in zip(events, ("record_created", "record_updated"), (1_000_000, 2_000_000)):
        assert_signed_event(keys, event, kind=kind, owner="alice", record_id=first["id"])
        assert event["time_us"] == time
    assert_signed_event(keys, events[-1], kind="record_read", owner="alice", record_id=first["id"])


def test_read_returns_verified_stored_evidence_and_plaintext_without_regeneration(seeded):
    config, keys = seeded
    saved = save(seeded)
    row, plaintext = records.read_record(
        config, keys, owner="alice", record_id=saved["id"],
        src_ip="192.0.2.10", session_ref="test-session",
    )
    assert row == saved
    assert plaintext == {"title": "Private title", "body": "Private body"}
    assert stored_rows(config, "records") == [saved]
    events = stored_rows(config, "events")
    assert len(events) == 2
    assert_signed_event(keys, events[-1], kind="record_read", owner="alice", record_id=saved["id"])


def test_listing_contains_only_verified_owned_summary_fields(seeded):
    config, keys = seeded
    alice = save(seeded)
    bob = save(seeded, owner="bob", title="Bob title")
    listed = records.list_records(
        config, keys, owner="bob", src_ip="192.0.2.10", session_ref="test-session",
    )
    assert listed == [{
        "id": bob["id"], "title": "Bob title", "version": 1,
        "created_at_us": bob["created_at_us"], "updated_at_us": bob["updated_at_us"],
    }]
    assert alice["id"] != listed[0]["id"]


@pytest.mark.parametrize("operation", ["read", "edit"])
def test_foreign_existing_access_commits_one_signed_denial_before_raising(seeded, operation):
    config, keys = seeded
    saved = save(seeded)
    if operation == "read":
        access = lambda: records.read_record(
            config, keys, owner="bob", record_id=saved["id"],
            src_ip="192.0.2.10", session_ref="test-session",
        )
    else:
        access = lambda: save(seeded, owner="bob", record_id=saved["id"])
    with pytest.raises(records.RecordDenied):
        access()
    # A separate connection sees the event after the exception reaches the caller.
    events = stored_rows(config, "events")
    assert len(events) == 2
    assert_signed_event(keys, events[-1], kind="foreign_record_denied", owner="bob", record_id=saved["id"])
    assert stored_rows(config, "records") == [saved]


@pytest.mark.parametrize("operation", ["read", "edit"])
def test_missing_record_is_missing_and_does_not_emit_foreign_denial(seeded, operation):
    config, keys = seeded
    missing_id = "0123456789abcdef0123456789abcdef"
    with pytest.raises(records.RecordMissing):
        if operation == "read":
            records.read_record(
                config, keys, owner="bob", record_id=missing_id,
                src_ip="192.0.2.10", session_ref="test-session",
            )
        else:
            save(seeded, owner="bob", record_id=missing_id)
    assert stored_rows(config, "records") == []
    assert stored_rows(config, "events") == []


@pytest.mark.parametrize("operation", ["read", "list", "edit"])
def test_corrupt_owned_record_commits_integrity_failure_and_preserves_bad_row(seeded, operation):
    config, keys = seeded
    saved = save(seeded)
    with transaction(config) as conn:
        conn.execute("UPDATE records SET sha256_hex=? WHERE id=?", ("0" * 64, saved["id"]))
    corrupted = stored_rows(config, "records")
    with pytest.raises(IntegrityError):
        if operation == "read":
            records.read_record(
                config, keys, owner="alice", record_id=saved["id"],
                src_ip="192.0.2.10", session_ref="test-session",
            )
        elif operation == "list":
            records.list_records(
                config, keys, owner="alice", src_ip="192.0.2.10", session_ref="test-session",
            )
        else:
            save(seeded, record_id=saved["id"], title="Replacement", body="Replacement")
    assert stored_rows(config, "records") == corrupted
    events = stored_rows(config, "events")
    assert len(events) == 2
    assert_signed_event(keys, events[-1], kind="integrity_failure", owner="alice", record_id=saved["id"])


@pytest.mark.parametrize("damage", ["corrupt", "missing"])
def test_history_read_fails_as_a_whole_for_corrupt_or_missing_snapshot(seeded, damage):
    config, keys = seeded
    saved = save(seeded)
    save(seeded, record_id=saved["id"], body="Second private body")
    with transaction(config) as conn:
        if damage == "corrupt":
            conn.execute(
                "UPDATE record_versions SET sha256_hex=? WHERE id=? AND version=1",
                ("0" * 64, saved["id"]),
            )
        else:
            conn.execute(
                "DELETE FROM record_versions WHERE id=? AND version=2",
                (saved["id"],),
            )
    with pytest.raises(IntegrityError):
        records.read_record_history(
            config, keys, owner="alice", record_id=saved["id"],
            src_ip="192.0.2.10", session_ref="test-session",
        )


@pytest.mark.parametrize("title,body", [
    ("", "body"), (" \t", "body"), ("t" * 121, "body"),
    ("title", ""), ("title", "\n\t"), ("title", "b" * 10_001),
])
def test_invalid_form_data_leaves_no_record_or_event(seeded, title, body):
    config, _ = seeded
    with pytest.raises(ValueError):
        save(seeded, title=title, body=body)
    assert stored_rows(config, "records") == []
    assert stored_rows(config, "events") == []


def test_valid_minimum_and_maximum_form_lengths_are_preserved(seeded):
    _, keys = seeded
    for title, body in [("é", "x"), ("é" * 120, "x" * 10_000)]:
        saved = save(seeded, title=title, body=body)
        assert open_record(keys, saved) == {"title": title, "body": body}


def test_concurrent_edits_serialize_to_distinct_increasing_versions(seeded):
    config, keys = seeded
    first = save(seeded)
    start = Barrier(2)

    def edit(body):
        start.wait(timeout=5)
        return save(seeded, record_id=first["id"], body=body)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(edit, body) for body in ("Edit one", "Edit two")]
        results = [future.result(timeout=10) for future in futures]
    assert sorted(row["version"] for row in results) == [2, 3]
    latest = max(results, key=lambda row: row["version"])
    assert stored_rows(config, "records") == [latest]
    assert open_record(keys, latest)["body"] in {"Edit one", "Edit two"}
    events = stored_rows(config, "events")
    assert [event["kind"] for event in events] == ["record_created", "record_updated", "record_updated"]
    assert all(verify_app_event(keys, event) for event in events)


@pytest.mark.parametrize("editing", [False, True])
def test_failed_save_rolls_back_ciphertext_and_success_event_together(seeded, monkeypatch, editing):
    config, _ = seeded
    original = save(seeded) if editing else None
    before_records = stored_rows(config, "records")
    before_events = stored_rows(config, "events")
    append = records.append_app_event

    def insert_then_fail(conn, keys, payload):
        append(conn, keys, payload)
        raise RuntimeError("Injected save failure after event insertion")

    monkeypatch.setattr(records, "append_app_event", insert_then_fail)
    with pytest.raises(RuntimeError, match="Injected save failure"):
        save(seeded, record_id=original["id"] if original else None, body="Changed body")
    assert stored_rows(config, "records") == before_records
    assert stored_rows(config, "events") == before_events


def test_image_create_keep_replace_remove_preserves_exact_version_evidence(seeded):
    config, keys = seeded
    png = tiny_image("PNG")
    jpeg = tiny_image("JPEG")
    first = save(seeded, image_action="replace", image_bytes=png, image_mime="image/png")
    kept = save(seeded, record_id=first["id"], body="Text edit keeps the image")
    replaced = save(
        seeded, record_id=first["id"], body="Image replacement", image_action="replace",
        image_bytes=jpeg, image_mime="image/jpeg",
    )
    removed = save(seeded, record_id=first["id"], body="Image removed", image_action="remove")

    assert [row["version"] for row in (first, kept, replaced, removed)] == [1, 2, 3, 4]
    assert all(row["envelope_schema"] == 2 for row in (first, kept, replaced, removed))
    assert open_record_image(keys, first) == ("image/png", png)
    assert open_record_image(keys, kept) == ("image/png", png)
    assert open_record_image(keys, replaced) == ("image/jpeg", jpeg)
    assert open_record_image(keys, removed) is None
    assert kept["image_nonce"] != first["image_nonce"]
    assert kept["image_ciphertext"] != first["image_ciphertext"]
    assert all(removed[field] is None for field in (
        "image_nonce", "image_ciphertext", "image_mime", "image_size",
        "image_plain_sha256", "image_cipher_sha256", "image_encrypt_ns", "image_hash_ns",
    ))
    assert stored_rows(config, "records") == [removed]
    assert stored_rows(config, "record_versions") == [first, kept, replaced, removed]
    history = records.read_record_history(
        config, keys, owner="alice", record_id=first["id"],
        src_ip="192.0.2.10", session_ref="test-session",
    )
    assert [open_record_image(keys, row) for row, _ in history] == [
        None, ("image/jpeg", jpeg), ("image/png", png), ("image/png", png),
    ]
    events = stored_rows(config, "events")
    assert [event["kind"] for event in events] == [
        "record_created", "record_updated", "record_updated", "record_updated", "record_read",
    ]
    for event in events:
        assert_signed_event(keys, event, kind=event["kind"], owner="alice", record_id=first["id"])


@pytest.mark.parametrize("image_action,image_bytes,image_mime", [
    ("replace", None, "image/png"),
    ("replace", b"damaged PNG", "image/png"),
    ("replace", tiny_image(), "image/jpeg"),
    ("replace", b"x" * 1_048_577, "image/png"),
    ("keep", tiny_image(), "image/png"),
    ("remove", tiny_image(), "image/png"),
    ("unknown", None, None),
], ids=[
    "replace-missing-bytes", "replace-malformed", "replace-mime-mismatch",
    "replace-oversize", "keep-with-upload", "remove-with-upload", "unknown-action",
])
def test_invalid_image_command_rejects_before_save_or_success_audit(
    seeded, image_action, image_bytes, image_mime,
):
    config, _ = seeded
    original = save(seeded)
    before_records = stored_rows(config, "records")
    before_versions = stored_rows(config, "record_versions")
    before_events = stored_rows(config, "events")
    with pytest.raises(ValueError):
        save(
            seeded, record_id=original["id"], image_action=image_action,
            image_bytes=image_bytes, image_mime=image_mime,
        )
    assert stored_rows(config, "records") == before_records
    assert stored_rows(config, "record_versions") == before_versions
    assert stored_rows(config, "events") == before_events


def test_corrupt_historical_image_rejects_whole_history_and_signs_failure(seeded):
    config, keys = seeded
    first = save(
        seeded, image_action="replace", image_bytes=tiny_image(), image_mime="image/png",
    )
    latest = save(seeded, record_id=first["id"], body="Current plaintext must stay hidden")
    with transaction(config) as conn:
        conn.execute(
            "UPDATE record_versions SET image_ciphertext=? WHERE id=? AND version=1",
            (b"\x00" + first["image_ciphertext"][1:], first["id"]),
        )
    bad_versions = stored_rows(config, "record_versions")
    with pytest.raises(IntegrityError):
        records.read_record_history(
            config, keys, owner="alice", record_id=first["id"],
            src_ip="192.0.2.10", session_ref="test-session",
        )
    assert stored_rows(config, "records") == [latest]
    assert stored_rows(config, "record_versions") == bad_versions
    events = stored_rows(config, "events")
    assert [event["kind"] for event in events] == [
        "record_created", "record_updated", "integrity_failure",
    ]
    assert_signed_event(keys, events[-1], kind="integrity_failure", owner="alice", record_id=first["id"])


def test_current_snapshot_mismatch_in_image_measurement_is_integrity_failure(seeded):
    config, keys = seeded
    saved = save(
        seeded, image_action="replace", image_bytes=tiny_image(), image_mime="image/png",
    )
    with transaction(config) as conn:
        conn.execute(
            "UPDATE record_versions SET image_hash_ns=image_hash_ns+1 WHERE id=? AND version=1",
            (saved["id"],),
        )
    with pytest.raises(IntegrityError):
        records.read_record_history(
            config, keys, owner="alice", record_id=saved["id"],
            src_ip="192.0.2.10", session_ref="test-session",
        )
    events = stored_rows(config, "events")
    assert [event["kind"] for event in events] == ["record_created", "integrity_failure"]
    assert_signed_event(keys, events[-1], kind="integrity_failure", owner="alice", record_id=saved["id"])


@pytest.mark.parametrize("operation", ["read", "history", "edit"])
def test_foreign_owner_is_preflighted_before_full_record_row_fetch(seeded, monkeypatch, operation):
    config, _ = seeded
    saved = save(
        seeded, image_action="replace", image_bytes=tiny_image(), image_mime="image/png",
    )
    statements = []
    original_transaction = records.transaction

    class TracedConnection:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, parameters=()):
            statements.append(" ".join(sql.upper().split()))
            return self.conn.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    @contextmanager
    def traced_transaction(*args, **kwargs):
        with original_transaction(*args, **kwargs) as conn:
            yield TracedConnection(conn)

    monkeypatch.setattr(records, "transaction", traced_transaction)
    with pytest.raises(records.RecordDenied):
        if operation == "read":
            records.read_record(
                config, seeded[1], owner="bob", record_id=saved["id"],
                src_ip="192.0.2.10", session_ref="test-session",
            )
        elif operation == "history":
            records.read_record_history(
                config, seeded[1], owner="bob", record_id=saved["id"],
                src_ip="192.0.2.10", session_ref="test-session",
            )
        else:
            save(seeded, owner="bob", record_id=saved["id"])
    record_selects = [sql for sql in statements if "FROM RECORDS" in sql]
    assert record_selects == ["SELECT OWNER FROM RECORDS WHERE ID=?"]


@pytest.mark.parametrize("editing", [False, True])
def test_failed_image_save_rolls_back_record_snapshot_and_signed_event(seeded, monkeypatch, editing):
    config, keys = seeded
    original = save(
        seeded, image_action="replace", image_bytes=tiny_image(), image_mime="image/png",
    ) if editing else None
    before = {table: stored_rows(config, table) for table in (
        "records", "record_versions", "events",
    )}
    append = records.append_app_event

    def append_then_fail(conn, keys, payload):
        append(conn, keys, payload)
        raise RuntimeError("Injected image audit failure")

    monkeypatch.setattr(records, "append_app_event", append_then_fail)
    with pytest.raises(RuntimeError, match="Injected image audit failure"):
        save(
            seeded, record_id=original["id"] if original else None,
            image_action="replace", image_bytes=tiny_image("JPEG"), image_mime="image/jpeg",
        )
    for table, expected in before.items():
        assert stored_rows(config, table) == expected
    assert all(verify_app_event(keys, event) for event in before["events"])

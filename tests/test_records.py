"""Record service contracts exercised against real SQLite and cryptography."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from threading import Barrier
from uuid import UUID

import pytest
from werkzeug.security import generate_password_hash

from security_lab import records
from security_lab.audit import verify_app_event
from security_lab.crypto import IntegrityError, open_record
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


def save(seeded, *, owner="alice", record_id=None, title="Private title", body="Private body"):
    config, keys = seeded
    return records.save_record(
        config, keys, owner=owner, record_id=record_id, title=title, body=body,
        src_ip="192.0.2.10", session_ref="test-session",
    )


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

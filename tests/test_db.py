import sqlite3
from contextlib import closing
from dataclasses import replace

import pytest

from security_lab.db import connect, initialize_database, transaction
from security_lab.crypto import open_record


IMAGE_COLUMNS = {
    "image_nonce", "image_ciphertext", "image_mime", "image_size",
    "image_plain_sha256", "image_cipher_sha256", "image_encrypt_ns",
    "image_hash_ns",
}
LEGACY_COLUMNS = (
    "id", "owner", "version", "nonce_b64", "ciphertext_b64", "sha256_hex",
    "signature_b64", "created_at_us", "updated_at_us", "generated_at_us",
    "plaintext_bytes", "ciphertext_bytes", "envelope_bytes", "encryption_ns",
    "hashing_ns", "signing_ns",
)
LEGACY_DECLARATIONS = (
    "id TEXT NOT NULL", "owner TEXT NOT NULL", "version INTEGER NOT NULL",
    "nonce_b64 TEXT NOT NULL", "ciphertext_b64 TEXT NOT NULL",
    "sha256_hex TEXT NOT NULL", "signature_b64 TEXT NOT NULL",
    "created_at_us INTEGER NOT NULL", "updated_at_us INTEGER NOT NULL",
    "generated_at_us INTEGER NOT NULL", "plaintext_bytes INTEGER NOT NULL",
    "ciphertext_bytes INTEGER NOT NULL", "envelope_bytes INTEGER NOT NULL",
    "encryption_ns INTEGER NOT NULL", "hashing_ns INTEGER NOT NULL",
    "signing_ns INTEGER NOT NULL",
)
FROZEN_EVIDENCE_FIELDS = (
    "nonce_b64", "ciphertext_b64", "sha256_hex", "signature_b64",
    "created_at_us", "updated_at_us", "generated_at_us", "plaintext_bytes",
    "ciphertext_bytes", "envelope_bytes", "encryption_ns", "hashing_ns",
    "signing_ns",
)


def _user_row():
    return ("alice", "user", "hash", 1)


def _insert_user(connection):
    connection.execute(
        "INSERT INTO users (username, role, password_hash, created_at_us) "
        "VALUES (?, ?, ?, ?)",
        _user_row(),
    )


def test_schema_idempotent(config):
    initialize_database(config)
    with closing(connect(config)) as connection, connection:
        _insert_user(connection)

    initialize_database(config)

    with closing(connect(config)) as connection, connection:
        rows = connection.execute(
            "SELECT username, role, password_hash, created_at_us FROM users"
        ).fetchall()
    assert [tuple(row) for row in rows] == [_user_row()]


def test_fresh_schema_has_versioned_image_fields_after_repeated_startup(config):
    initialize_database(config)
    initialize_database(config)
    with closing(connect(config)) as connection:
        for table in ("records", "record_versions"):
            columns = {row["name"]: row for row in connection.execute(
                f"PRAGMA table_info({table})"
            )}
            assert columns["envelope_schema"]["notnull"] == 1
            assert columns["envelope_schema"]["dflt_value"] == "1"
            assert IMAGE_COLUMNS <= columns.keys()
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE name='record_versions_v1_backfill'"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("history_already_present", [False, True])
def test_legacy_database_migration_keeps_signed_v1_bytes_and_is_idempotent(
    config, keys, history_already_present,
):
    # Build a database with pre-image columns, including the historical case
    # where a snapshot and its backfill marker already exist.
    from test_crypto import BODY, TITLE, seal as make_legacy_evidence

    old_config = replace(config, data_dir=config.data_dir / "old")
    old_config.data_dir.mkdir(parents=True)
    row = make_legacy_evidence(keys, record_id="frozen-v1", owner="alice")
    before = tuple(row[field] for field in FROZEN_EVIDENCE_FIELDS)
    db_path = old_config.data_dir / "lab.sqlite3"
    with closing(sqlite3.connect(db_path)) as connection, connection:
        connection.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL, "
            "password_hash TEXT NOT NULL, created_at_us INTEGER NOT NULL)"
        )
        connection.execute("INSERT INTO users VALUES ('alice','user','hash',1)")
        connection.execute("CREATE TABLE schema_migrations (name TEXT PRIMARY KEY)")
        connection.execute("CREATE TABLE records (" + ",".join(LEGACY_DECLARATIONS)
                           + ",PRIMARY KEY(id))")
        if history_already_present:
            connection.execute("CREATE TABLE record_versions ("
                               + ",".join(LEGACY_DECLARATIONS)
                               + ",PRIMARY KEY(id,version))")
        names = ",".join(LEGACY_COLUMNS)
        placeholders = ",".join("?" for _ in LEGACY_COLUMNS)
        values = tuple(row[field] for field in LEGACY_COLUMNS)
        connection.execute(f"INSERT INTO records ({names}) VALUES ({placeholders})", values)
        if history_already_present:
            connection.execute(
                f"INSERT INTO record_versions ({names}) VALUES ({placeholders})", values,
            )
            connection.execute(
                "INSERT INTO schema_migrations VALUES ('record_versions_v1_backfill')"
            )

    initialize_database(old_config)
    initialize_database(old_config)
    with closing(connect(old_config)) as connection:
        current = dict(connection.execute("SELECT * FROM records").fetchone())
        snapshots = [dict(snapshot) for snapshot in connection.execute(
            "SELECT * FROM record_versions WHERE id='frozen-v1'"
        )]
        assert len(snapshots) == 1
        for saved in (current, snapshots[0]):
            assert tuple(saved[field] for field in FROZEN_EVIDENCE_FIELDS) == before
            assert saved["envelope_schema"] == 1
            assert all(saved[field] is None for field in IMAGE_COLUMNS)
            assert open_record(keys, saved) == {"title": TITLE, "body": BODY}
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE name='record_versions_v1_backfill'"
        ).fetchone()[0] == 1


def test_transaction_rolls_back(config):
    initialize_database(config)

    with pytest.raises(RuntimeError, match="abort"):
        with transaction(config) as connection:
            _insert_user(connection)
            raise RuntimeError("abort")

    with closing(connect(config)) as connection, connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_distinct_connections(config):
    initialize_database(config)

    with transaction(config) as first:
        _insert_user(first)

    with closing(connect(config)) as second, second:
        assert second.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert second.execute(
            "SELECT username FROM users WHERE username = ?", ("alice",)
        ).fetchone()["username"] == "alice"

    with closing(connect(config)) as third, third:
        assert third.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert third.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("table", "insert_sql", "values"),
    [
        (
            "users.username",
            "INSERT INTO users "
            "(username, role, password_hash, created_at_us) VALUES (?, ?, ?, ?)",
            (None, "user", "hash", 1),
        ),
        (
            "users.role",
            "INSERT INTO users "
            "(username, role, password_hash, created_at_us) VALUES (?, ?, ?, ?)",
            ("alice", None, "hash", 1),
        ),
        (
            "records.id",
            "INSERT INTO records "
            "(id, owner, version, nonce_b64, ciphertext_b64, sha256_hex, "
            "signature_b64, created_at_us, updated_at_us, generated_at_us, "
            "plaintext_bytes, ciphertext_bytes, envelope_bytes, encryption_ns, "
            "hashing_ns, signing_ns) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (None, "alice", 1, "bg==", "YQ==", "0" * 64, "c2ln", 1, 1, 1, 1, 1, 1, 1, 1, 1),
        ),
        (
            "alerts.id",
            "INSERT INTO alerts "
            "(id, domain, rule, src_ip, username, session_ref, time_us, "
            "trigger_event_id, severity, summary, evidence_json, dedup_key) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (None, "lab", "rule", "127.0.0.1", None, None, 1, "event", "low",
             "summary", '{"event_ids":[],"alert_ids":[]}', "dedup"),
        ),
        (
            "blocks.ip",
            "INSERT INTO blocks (ip, created_at_us, created_by, reason) "
            "VALUES (?, ?, ?, ?)",
            (None, 1, "alice", "test"),
        ),
        (
            "status.key",
            "INSERT INTO status (key, value_json) VALUES (?, ?)",
            (None, "{}"),
        ),
    ],
)
def test_required_columns_reject_explicit_null(config, table, insert_sql, values):
    initialize_database(config)
    with closing(connect(config)) as connection, connection:
        if table == "records.id":
            _insert_user(connection)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert_sql, values)
        table_name = table.split(".")[0]
        expected = 0
        assert connection.execute(
            f"SELECT COUNT(*) FROM {table_name}"
        ).fetchone()[0] == expected

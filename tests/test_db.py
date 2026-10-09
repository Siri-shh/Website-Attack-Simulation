import sqlite3
from contextlib import closing

import pytest

from security_lab.db import connect, initialize_database, transaction


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

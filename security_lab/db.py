"""SQLite connection and transaction helpers."""
from contextlib import closing, contextmanager
import sqlite3
from pathlib import Path
from typing import Iterator

from .config import Config


_IMAGE_COLUMNS = (
    ("envelope_schema", "INTEGER NOT NULL DEFAULT 1"),
    ("image_nonce", "BLOB"),
    ("image_ciphertext", "BLOB"),
    ("image_mime", "TEXT"),
    ("image_size", "INTEGER"),
    ("image_plain_sha256", "TEXT"),
    ("image_cipher_sha256", "TEXT"),
    ("image_encrypt_ns", "INTEGER"),
    ("image_hash_ns", "INTEGER"),
)


def connect(config: Config) -> sqlite3.Connection:
    """Open a configured connection to the lab database."""
    config.data_dir.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        str(config.data_dir / "lab.sqlite3"),
        timeout=5.0,
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
    except BaseException:
        connection.close()
        raise
    return connection


@contextmanager
def transaction(config: Config) -> Iterator[sqlite3.Connection]:
    """Run an immediate transaction and close its connection on exit."""
    connection = connect(config)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    finally:
        connection.close()


def initialize_database(config: Config) -> None:
    """Apply the packaged database schema."""
    schema_path = Path(__file__).with_name("schema.sql")
    schema = schema_path.read_text(encoding="utf-8")
    with closing(connect(config)) as connection:
        connection.executescript(schema)

    # SQLite retains old table definitions under CREATE TABLE IF NOT EXISTS.
    # Add every missing field before snapshot backfill in the same transaction.
    # Legacy ciphertext, hashes and signatures are never rewritten.
    with transaction(config) as conn:
        for table in ("records", "record_versions"):
            present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, declaration in _IMAGE_COLUMNS:
                if name not in present:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)",
            ("image_envelope_v2_columns",),
        )

        # Backfill once. The marker prevents later startup from silently
        # repairing missing history, even on a migrated old database.
        migration = "record_versions_v1_backfill"
        applied = conn.execute(
            "SELECT 1 FROM schema_migrations WHERE name = ?", (migration,)
        ).fetchone()
        if applied is None:
            conn.execute(
                "INSERT INTO record_versions (id, version, owner, nonce_b64, "
                "ciphertext_b64, sha256_hex, signature_b64, created_at_us, "
                "updated_at_us, generated_at_us, plaintext_bytes, "
                "ciphertext_bytes, envelope_bytes, encryption_ns, hashing_ns, "
                "signing_ns) SELECT id, version, owner, nonce_b64, "
                "ciphertext_b64, sha256_hex, signature_b64, created_at_us, "
                "updated_at_us, generated_at_us, plaintext_bytes, "
                "ciphertext_bytes, envelope_bytes, encryption_ns, hashing_ns, "
                "signing_ns FROM records"
            )
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES (?)", (migration,)
            )

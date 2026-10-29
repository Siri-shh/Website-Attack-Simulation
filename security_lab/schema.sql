PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    password_hash TEXT NOT NULL,
    created_at_us INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id TEXT NOT NULL PRIMARY KEY,
    owner TEXT NOT NULL REFERENCES users(username),
    version INTEGER NOT NULL CHECK (version >= 1),
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    sha256_hex TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    created_at_us INTEGER NOT NULL,
    updated_at_us INTEGER NOT NULL,
    generated_at_us INTEGER NOT NULL,
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes >= 0),
    envelope_bytes INTEGER NOT NULL CHECK (envelope_bytes >= 0),
    encryption_ns INTEGER NOT NULL CHECK (encryption_ns >= 0),
    hashing_ns INTEGER NOT NULL CHECK (hashing_ns >= 0),
    signing_ns INTEGER NOT NULL CHECK (signing_ns >= 0),
    envelope_schema INTEGER NOT NULL DEFAULT 1,
    image_nonce BLOB,
    image_ciphertext BLOB,
    image_mime TEXT,
    image_size INTEGER,
    image_plain_sha256 TEXT,
    image_cipher_sha256 TEXT,
    image_encrypt_ns INTEGER,
    image_hash_ns INTEGER
);
CREATE INDEX IF NOT EXISTS records_owner_idx ON records(owner);

CREATE TABLE IF NOT EXISTS record_versions (
    id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    owner TEXT NOT NULL REFERENCES users(username),
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    sha256_hex TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    created_at_us INTEGER NOT NULL,
    updated_at_us INTEGER NOT NULL,
    generated_at_us INTEGER NOT NULL,
    plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes >= 0),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes >= 0),
    envelope_bytes INTEGER NOT NULL CHECK (envelope_bytes >= 0),
    encryption_ns INTEGER NOT NULL CHECK (encryption_ns >= 0),
    hashing_ns INTEGER NOT NULL CHECK (hashing_ns >= 0),
    signing_ns INTEGER NOT NULL CHECK (signing_ns >= 0),
    envelope_schema INTEGER NOT NULL DEFAULT 1,
    image_nonce BLOB,
    image_ciphertext BLOB,
    image_mime TEXT,
    image_size INTEGER,
    image_plain_sha256 TEXT,
    image_cipher_sha256 TEXT,
    image_encrypt_ns INTEGER,
    image_hash_ns INTEGER,
    PRIMARY KEY (id, version)
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    event_id TEXT NOT NULL,
    time_us INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    dst_port INTEGER,
    username TEXT,
    session_ref TEXT,
    record_id TEXT,
    outcome TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature_b64 TEXT,
    capture_id TEXT,
    frame_number INTEGER,
    UNIQUE(domain, event_id)
);
CREATE INDEX IF NOT EXISTS events_domain_kind_src_user_time_idx
    ON events(domain, kind, src_ip, username, time_us);
CREATE INDEX IF NOT EXISTS events_domain_session_time_idx
    ON events(domain, session_ref, time_us);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT NOT NULL PRIMARY KEY,
    domain TEXT NOT NULL,
    rule TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    username TEXT,
    session_ref TEXT,
    time_us INTEGER NOT NULL,
    trigger_event_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    UNIQUE(domain, rule, dedup_key)
);
CREATE INDEX IF NOT EXISTS alerts_domain_rule_src_user_time_idx
    ON alerts(domain, rule, src_ip, username, time_us);

CREATE TABLE IF NOT EXISTS blocks (
    ip TEXT NOT NULL PRIMARY KEY,
    created_at_us INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS status (
    key TEXT NOT NULL PRIMARY KEY,
    value_json TEXT NOT NULL
);

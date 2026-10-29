"""Real temporary-file lifecycle tests; no runtime data or services are used."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from security_lab.db import initialize_database, transaction
from security_lab.identity import ensure_certificate, load_or_create_keys


SECRET_FILES = (
    "aes.key", "signing.key", "storage-session.key", "console-session.key"
)


def _secret_files(config):
    return {name: (config.data_dir / "keys" / name).read_bytes() for name in SECRET_FILES}


def _public_bytes(keys):
    return keys.signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _certificate(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def _protected_row(config, kind):
    """Insert minimal complete persisted evidence; its existence forbids key reset."""
    with transaction(config) as conn:
        if kind == "record":
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                ("bob", "user", "unused-test-hash", 1),
            )
            conn.execute(
                "INSERT INTO records (id,owner,version,nonce_b64,ciphertext_b64,sha256_hex,"
                "signature_b64,created_at_us,updated_at_us,generated_at_us,plaintext_bytes,"
                "ciphertext_bytes,envelope_bytes,encryption_ns,hashing_ns,signing_ns) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("record-1", "bob", 1, "bm9uY2U=", "Y2lwaGVydGV4dA==",
                 "0" * 64, "c2lnbmF0dXJl", 1, 1, 1, 1, 16, 32, 1, 1, 1),
            )
        else:
            conn.execute(
                "INSERT INTO events (domain, event_id, time_us, kind, src_ip, "
                "outcome, payload_json, signature_b64) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("live", "event-1", 1, "login_success" if kind == "signed_event" else "connection_attempt", "127.0.0.1",
                 "ok" if kind == "signed_event" else "observed", "{}",
                 "c2lnbmF0dXJl" if kind == "signed_event" else None),
            )


def test_keys_persist_as_independent_32_byte_secrets(config):
    # Catch replacement on startup, shared app secrets, or incorrect file encoding.
    initialize_database(config)
    first = load_or_create_keys(config)
    saved = _secret_files(config)
    second = load_or_create_keys(config)

    assert len(first.aes_key) == 32
    assert len(first.storage_session_secret) == 32
    assert len(first.console_session_secret) == 32
    assert all(len(value) == 32 for value in saved.values())
    assert len(set(saved.values())) == 4
    assert saved["aes.key"] == first.aes_key == second.aes_key
    assert saved["storage-session.key"] == first.storage_session_secret == second.storage_session_secret
    assert saved["console-session.key"] == first.console_session_secret == second.console_session_secret
    assert saved["signing.key"] == first.signing_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    assert _public_bytes(first) == _public_bytes(second)
    assert saved == _secret_files(config)
    assert {entry.name for entry in (config.data_dir / "keys").iterdir()} == set(SECRET_FILES)


def test_keyring_representation_hides_secret_material(config):
    # Catch raw secrets leaking when an exception or debugger prints the key ring.
    initialize_database(config)
    keys = load_or_create_keys(config)
    text = repr(keys)
    private = keys.signing_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    for secret in (keys.aes_key, private, keys.storage_session_secret, keys.console_session_secret):
        assert repr(secret) not in text
        assert secret.hex() not in text


@pytest.mark.parametrize("name", SECRET_FILES)
@pytest.mark.parametrize("length", [0, 31, 33])
def test_malformed_secret_is_rejected_without_replacing_files(config, name, length):
    # Catch accepting non-32-byte material or quietly overwriting a corrupt identity.
    initialize_database(config)
    load_or_create_keys(config)
    (config.data_dir / "keys" / name).write_bytes(b"x" * length)
    before = _secret_files(config)

    with pytest.raises(RuntimeError, match=name):
        load_or_create_keys(config)

    assert _secret_files(config) == before


@pytest.mark.parametrize("name", SECRET_FILES)
@pytest.mark.parametrize("kind", ["record", "signed_event", "network_event"])
def test_missing_secret_over_protected_data_fails_without_regeneration(config, name, kind):
    # Catch loss of encrypted records or signed evidence after a partial keys-directory loss.
    initialize_database(config)
    load_or_create_keys(config)
    _protected_row(config, kind)
    missing = config.data_dir / "keys" / name
    missing.unlink()
    remaining = {n: (config.data_dir / "keys" / n).read_bytes() for n in SECRET_FILES if n != name}

    with pytest.raises(RuntimeError, match=name):
        load_or_create_keys(config)

    assert not missing.exists()
    assert remaining == {n: (config.data_dir / "keys" / n).read_bytes() for n in remaining}


def test_all_missing_secrets_over_existing_record_create_no_replacements(config):
    # Catch sequential creation before checking whether protected evidence already exists.
    initialize_database(config)
    _protected_row(config, "record")

    with pytest.raises(RuntimeError, match="missing|Missing"):
        load_or_create_keys(config)

    assert not any((config.data_dir / "keys" / name).exists() for name in SECRET_FILES)


def test_certificate_is_current_self_signed_rsa_with_configured_sans(config):
    # Catch wrong algorithm, invalid lifetime, omitted IP SANs, or regeneration on restart.
    config = replace(config, server_ip="192.0.2.10", tls_names=("localhost", "127.0.0.1", "192.0.2.10", "lab.example"))
    before = datetime.now(timezone.utc)
    cert_path, key_path = ensure_certificate(config)
    cert = _certificate(cert_path)
    after = datetime.now(timezone.utc)
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    assert cert_path == config.data_dir / "keys" / "server.crt"
    assert key_path == config.data_dir / "keys" / "server.key"
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert private_key.key_size == 2048
    assert isinstance(cert.public_key(), rsa.RSAPublicKey)
    assert cert.public_key().public_numbers() == private_key.public_key().public_numbers()
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    assert cert.subject == cert.issuer
    assert "lab" in cert.subject.rfc4514_string().lower()
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    assert cert.not_valid_before_utc <= after
    assert cert.not_valid_after_utc > before
    assert before - timedelta(minutes=10) <= cert.not_valid_before_utc
    assert abs((cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds() - 365 * 86400) <= 600
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == {"localhost", "lab.example"}
    assert set(san.get_values_for_type(x509.IPAddress)) == {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("192.0.2.10")}
    original_cert = cert_path.read_bytes()
    original_key = key_path.read_bytes()

    assert ensure_certificate(config) == (cert_path, key_path)
    assert _certificate(cert_path).fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())
    assert cert_path.read_bytes() == original_cert
    assert key_path.read_bytes() == original_key


def test_explicit_certificate_renewal_preserves_all_application_secrets(config):
    # Catch ignored renewal or certificate renewal resetting encrypted/signing/session identities.
    initialize_database(config)
    keys = load_or_create_keys(config)
    application_secrets = _secret_files(config)
    cert_path, key_path = ensure_certificate(config)
    original = _certificate(cert_path).fingerprint(hashes.SHA256())

    assert ensure_certificate(config, renew=True) == (cert_path, key_path)

    assert _certificate(cert_path).fingerprint(hashes.SHA256()) != original
    assert _secret_files(config) == application_secrets
    assert _public_bytes(load_or_create_keys(config)) == _public_bytes(keys)


def test_san_mismatch_requires_explicit_renewal(config):
    # Catch silently replacing a previously trusted certificate when deployment names change.
    cert_path, key_path = ensure_certificate(config)
    original_cert = cert_path.read_bytes()
    original_key = key_path.read_bytes()
    changed = replace(config, server_ip="192.0.2.20", tls_names=("localhost", "127.0.0.1", "192.0.2.20"))

    with pytest.raises(RuntimeError, match="renew-certificate"):
        ensure_certificate(changed)

    assert cert_path.read_bytes() == original_cert
    assert key_path.read_bytes() == original_key
    assert ensure_certificate(changed, renew=True) == (cert_path, key_path)
    san = _certificate(cert_path).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("192.0.2.20") in san.get_values_for_type(x509.IPAddress)
    assert _certificate(cert_path).fingerprint(hashes.SHA256()) != x509.load_pem_x509_certificate(original_cert).fingerprint(hashes.SHA256())

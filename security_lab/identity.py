"""Persistent application identities and lab HTTPS certificate lifecycle.

The launcher must initialize identities before it starts server threads.
"""

from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sqlite3
import tempfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from .config import Config


@dataclass(frozen=True)
class KeyRing:
    aes_key: bytes = field(repr=False)
    signing_key: Ed25519PrivateKey = field(repr=False)
    storage_session_secret: bytes = field(repr=False)
    console_session_secret: bytes = field(repr=False)


_SECRET_FILES = (
    "aes.key", "signing.key", "storage-session.key", "console-session.key"
)
_RENEW_HINT = "Run init --renew-certificate to explicitly renew the lab certificate."


def _read_secret(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError:
        raise RuntimeError(f"Cannot read required key file {path.name}") from None
    if len(raw) != 32:
        raise RuntimeError(f"Malformed required key file {path.name}: expected 32 bytes")
    return raw


def _has_protected_data(config: Config) -> bool:
    """Inspect existing SQLite read-only; inspection failure must never permit reset."""
    database = config.data_dir / "lab.sqlite3"
    if not database.exists():
        return False
    try:
        uri = database.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as conn:
            for table in ("records", "events"):
                # Table names are fixed internal identifiers, never user input.
                if conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                    return True
    except sqlite3.Error:
        raise RuntimeError("Cannot inspect lab.sqlite3; refusing to create missing keys") from None
    return False


def _atomic_write(path: Path, data: bytes, *, replace: bool = False) -> None:
    """Publish complete bytes with a private temporary file in the same directory.

    Hard-link publication is atomic and never overwrites an existing secret.
    Explicit certificate renewal uses atomic replacement instead.
    """
    temporary = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError:
                # Another initializer may already have published it.
                # The caller reloads and validates the actual persisted bytes.
                pass
    except OSError:
        raise RuntimeError(f"Cannot persist identity file {path.name}") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_or_create_keys(config: Config) -> KeyRing:
    """Load persistent secrets, refusing replacements over protected data."""
    directory = config.data_dir / "keys"
    missing = []
    # Preflight all files before publishing anything: malformed or protected
    # partial directories cannot cause a mixture of old and replacement keys.
    for name in _SECRET_FILES:
        path = directory / name
        if path.exists():
            _read_secret(path)
        else:
            missing.append(name)
    if missing and _has_protected_data(config):
        raise RuntimeError(
            "Missing required key file(s) " + ", ".join(missing)
            + "; existing records or events forbid replacement"
        )
    directory.mkdir(parents=True, exist_ok=True)
    for name in missing:
        if name == "signing.key":
            raw = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        else:
            raw = os.urandom(32)
        _atomic_write(directory / name, raw)
    # Always return the bytes actually published, including a concurrently
    # published file. No newly generated in-memory key escapes without storage.
    raw_keys = {name: _read_secret(directory / name) for name in _SECRET_FILES}
    return KeyRing(
        aes_key=raw_keys["aes.key"],
        signing_key=Ed25519PrivateKey.from_private_bytes(raw_keys["signing.key"]),
        storage_session_secret=raw_keys["storage-session.key"],
        console_session_secret=raw_keys["console-session.key"],
    )


def _configured_sans(config: Config) -> list[x509.GeneralName]:
    if not config.tls_names:
        raise RuntimeError("Certificate requires at least one configured TLS name")
    names = []
    for value in config.tls_names:
        try:
            name = x509.IPAddress(ipaddress.ip_address(value))
        except ValueError:
            try:
                name = x509.DNSName(value)
            except (TypeError, ValueError):
                raise RuntimeError("Invalid configured certificate DNS name") from None
        if name not in names:
            names.append(name)
    return names


def _validate_certificate(cert_path: Path, key_path: Path, sans: list[x509.GeneralName]) -> None:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        public_key = cert.public_key()
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 2048:
            raise ValueError("invalid private key")
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("invalid public key")
        if public_key.public_numbers() != private_key.public_key().public_numbers():
            raise ValueError("certificate/key mismatch")
        if cert.subject != cert.issuer or not isinstance(cert.signature_hash_algorithm, hashes.SHA256):
            raise ValueError("invalid self-signed certificate")
        public_key.verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
        )
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError("certificate outside validity period")
        actual_sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        # Do not leak parser or private-key exception details in startup errors.
        raise RuntimeError(f"Invalid lab certificate server.crt/server.key. {_RENEW_HINT}") from None
    if set(actual_sans) != set(sans):
        raise RuntimeError(f"Certificate SAN mismatch for configured TLS names. {_RENEW_HINT}")


def ensure_certificate(config: Config, *, renew: bool = False) -> tuple[Path, Path]:
    """Return certificate/key paths; renewal affects only the HTTPS identity."""
    directory = config.data_dir / "keys"
    cert_path, key_path = directory / "server.crt", directory / "server.key"
    sans = _configured_sans(config)
    if not renew and (cert_path.exists() or key_path.exists()):
        if not cert_path.exists() or not key_path.exists():
            raise RuntimeError(f"Incomplete lab certificate server.crt/server.key. {_RENEW_HINT}")
        _validate_certificate(cert_path, key_path, sans)
        return cert_path, key_path

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Educational Security Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Storage Security Lab"),
    ])
    # A small backdate tolerates ordinary clock skew while keeping a 365-day span.
    not_before = datetime.now(timezone.utc) - timedelta(minutes=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    directory.mkdir(parents=True, exist_ok=True)
    _atomic_write(key_path, key_bytes, replace=renew)
    _atomic_write(cert_path, cert_bytes, replace=renew)
    # Detect incomplete/interrupted publication rather than trusting an unmatched pair.
    _validate_certificate(cert_path, key_path, sans)
    return cert_path, key_path

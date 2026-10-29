"""Initialize, serve and explicitly reset the educational storage-security lab.

Documented lab defaults: bob/BobDemo!2026, alice/AliceDemo!2026,
admin/AdminDemo!2026. These credentials are demonstration accounts.
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile
from threading import Thread, current_thread, main_thread

from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

from .capture import CaptureWorker
from .config import load_config, utc_us
from .console import create_console_app
from .crypto import seal_record
from .db import initialize_database, transaction
from .identity import ensure_certificate, load_or_create_keys
from .pcap import analyze_pcap
from .records import _RECORD_FIELDS, insert_record_version
from .storage import create_storage_app


_REPOSITORY = Path(__file__).resolve().parent.parent
_SEED_USERS = (
    ("bob", "user", "BobDemo!2026"),
    ("alice", "user", "AliceDemo!2026"),
    ("admin", "admin", "AdminDemo!2026"),
)
_SEED_RECORDS = (
    ("00000000000000000000000000000001", "bob", "Bob's record", "Bob's ordinary demonstration record."),
    ("00000000000000000000000000000002", "alice", "Alice's record", "Alice's ordinary demonstration record."),
)
_MARKER_HINT = (
    "Inspect the recorded process before proceeding. Only after confirming that "
    "it is stale, remove just server.pid manually; preserve database, keys and captures."
)


def _seed(config, keys):
    """Add only missing defaults under one immediate transaction."""
    with transaction(config) as conn:
        for username, role, password in _SEED_USERS:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone() is None:
                conn.execute("INSERT INTO users VALUES(?,?,?,?)", (
                    username, role, generate_password_hash(password, method="scrypt"), utc_us(),
                ))
        for record_id, owner, title, body in _SEED_RECORDS:
            if conn.execute("SELECT 1 FROM records WHERE id=?", (record_id,)).fetchone() is not None:
                continue
            now = utc_us()
            row = seal_record(keys, record_id=record_id, owner=owner, version=1,
                              title=title, body=body, created_at_us=now, saved_at_us=now)
            conn.execute(
                "INSERT INTO records (" + ",".join(_RECORD_FIELDS) + ") VALUES ("
                + ",".join("?" for _ in _RECORD_FIELDS) + ")",
                tuple(row[column] for column in _RECORD_FIELDS),
            )
            insert_record_version(conn, row)


def _initialize(config, *, renew=False):
    config.data_dir.mkdir(parents=True, exist_ok=True)
    initialize_database(config)
    keys = load_or_create_keys(config)
    certificate = ensure_certificate(config, renew=renew)
    (config.data_dir / "captures").mkdir(exist_ok=True)
    _seed(config, keys)
    return keys, certificate


def _marker_error(path):
    return RuntimeError(f"Existing server.pid marker at {path}. {_MARKER_HINT}")


def _claim_marker(config):
    """Publish complete JSON atomically without replacing an existing marker."""
    config.data_dir.mkdir(parents=True, exist_ok=True)
    marker = config.data_dir / "server.pid"
    payload = json.dumps({"pid": os.getpid(), "started_at_us": utc_us()}, sort_keys=True).encode("utf-8")
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".server.pid.", suffix=".tmp", dir=config.data_dir)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, marker)
        except FileExistsError:
            raise _marker_error(marker) from None
        identity = marker.stat()
        return marker, payload, (identity.st_dev, identity.st_ino)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _release_marker(owned):
    """An operator-replaced marker belongs to its replacement, even on shutdown."""
    marker, payload, identity = owned
    try:
        current = marker.lstat()
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
            if marker.read_bytes() == payload:
                marker.unlink()
    except FileNotFoundError:
        pass


def _capture_unconfigured(config):
    health = {
        "state": "degraded", "started_at_us": None, "last_packet_at_us": None,
        "capture_path": None, "error": "Capture interface is not configured",
    }
    with transaction(config) as conn:
        conn.execute(
            "INSERT INTO status(key,value_json) VALUES('capture',?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
            (json.dumps(health, sort_keys=True),),
        )


def _wait_for_shutdown(threads):
    while True:
        for thread in threads:
            thread.join(timeout=0.2)
            if not thread.is_alive():
                raise RuntimeError("An owned HTTPS listener stopped unexpectedly")


@contextmanager
def _graceful_sigterm():
    """SIGTERM uses the same owned-resource cleanup as Ctrl-C."""
    if current_thread() is not main_thread():
        yield
        return

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _serve(config):
    owned_marker = _claim_marker(config)
    listeners, threads = [], []
    capture = None
    cleanup_errors = []
    try:
        keys, certificate = _initialize(config)
        tls = tuple(str(path) for path in certificate)
        apps = (create_storage_app(config, keys), create_console_app(config, keys))
        for port, app in zip((config.storage_port, config.console_port), apps):
            try:
                listener = make_server(config.bind_host, port, app, threaded=True, ssl_context=tls)
            except SystemExit as exc:
                # Werkzeug reports ordinary bind errors through SystemExit.
                raise RuntimeError(f"Cannot bind owned HTTPS listener on port {port}") from exc
            # Drain in-flight requests before releasing the reset/startup guard.
            listener.daemon_threads = False
            listener.block_on_close = True
            listeners.append(listener)
        for index, listener in enumerate(listeners):
            thread = Thread(target=listener.serve_forever, name=f"lab-https-{index}", daemon=True)
            threads.append(thread)
            thread.start()
        if config.capture_interface:
            capture = CaptureWorker(config, keys)
            capture.start()
        else:
            _capture_unconfigured(config)
            print("Capture interface is not configured; monitoring is degraded.", file=sys.stderr)
        print(f"Storage: https://{config.bind_host}:{config.storage_port}")
        print(f"Console: https://{config.bind_host}:{config.console_port}")
        _wait_for_shutdown(threads)
    except KeyboardInterrupt:
        pass
    finally:
        if capture is not None:
            try:
                capture.stop()
                if capture.health().get("state") != "stopped":
                    cleanup_errors.append("owned capture did not stop completely")
            except Exception as exc:
                cleanup_errors.append(f"owned capture shutdown failed: {exc}")
        for listener, thread in zip(listeners, threads):
            try:
                if thread.is_alive():
                    listener.shutdown()
                    thread.join(timeout=5.0)
                    if thread.is_alive():
                        cleanup_errors.append("owned HTTPS listener did not stop completely")
            except Exception as exc:
                cleanup_errors.append(f"owned HTTPS shutdown failed: {exc}")
        for listener in listeners:
            try:
                listener.server_close()
            except Exception as exc:
                cleanup_errors.append(f"owned HTTPS close failed: {exc}")
        if cleanup_errors:
            print("Shutdown incomplete; preserving server.pid: " + "; ".join(cleanup_errors), file=sys.stderr)
        else:
            _release_marker(owned_marker)
    if cleanup_errors:
        raise RuntimeError("Owned resource cleanup incomplete; inspect server.pid before recovery")


def _is_link_or_reparse(path):
    info = path.lstat()
    return (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def _safe_reset_directory(config):
    supplied = Path(config.data_dir).absolute()
    directory = supplied.resolve()
    repository = _REPOSITORY.resolve()
    if directory == Path(directory.anchor) or directory == repository or directory in repository.parents:
        raise RuntimeError("Refusing unsafe reset data_dir: filesystem root, repository or ancestor")
    protected = [repository / name for name in (".git", "security_lab", "tests", "docs")]
    protected.append(repository.parent / "Project")
    if any(directory == path or path in directory.parents for path in protected):
        raise RuntimeError("Refusing reset inside protected repository/reference directory")
    # Resolving a configured alias must not conceal a symlink or Windows junction.
    for path in (supplied, *supplied.parents):
        if path.exists() and _is_link_or_reparse(path):
            raise RuntimeError("Refusing reset through a symlink or reparse-point data_dir")
    if directory.exists() and not directory.is_dir():
        raise RuntimeError("Reset data_dir must be a directory")
    return directory


def _reset_targets(directory):
    """Preflight the bounded allowlist and entire captures subtree before deletion."""
    targets = [directory / name for name in ("lab.sqlite3", "lab.sqlite3-wal", "lab.sqlite3-shm", "captures")]
    for target in targets:
        if not target.exists() and not target.is_symlink():
            continue
        if _is_link_or_reparse(target) or target.resolve().parent != directory:
            raise RuntimeError("Refusing reset target outside data_dir or through a link/reparse point")
        if target.name == "captures":
            if not target.is_dir():
                raise RuntimeError("Reset captures target must be a directory")
            for entry in target.rglob("*"):
                if _is_link_or_reparse(entry) or directory not in entry.resolve().parents:
                    raise RuntimeError("Refusing unsafe capture deletion target")
                if not entry.is_file() and not entry.is_dir():
                    raise RuntimeError("Refusing unexpected capture deletion target type")
        elif not target.is_file():
            raise RuntimeError("Refusing unexpected database deletion target type")
    return targets


def _reset(config):
    directory = _safe_reset_directory(config)
    targets = _reset_targets(directory)
    owned_marker = _claim_marker(config)
    try:
        # Recheck after acquiring the shared serve/reset guard.
        targets = _reset_targets(directory)
        for target in targets:
            if target.name == "captures" and target.exists():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
        _initialize(config)
    finally:
        _release_marker(owned_marker)


def _parser():
    parser = argparse.ArgumentParser(
        prog="python -m security_lab",
        description="Educational lab defaults: bob/BobDemo!2026, alice/AliceDemo!2026, admin/AdminDemo!2026.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create missing lab data and identities; preserve existing records")
    init.add_argument("--renew-certificate", action="store_true")
    commands.add_parser("serve", help="Run two local HTTPS lab listeners")
    analyze = commands.add_parser("analyze-pcap", help="Analyze a stopped capture offline")
    analyze.add_argument("path", type=Path)
    reset = commands.add_parser("reset", help="Explicitly clear lab data/captures while preserving keys")
    reset.add_argument("--confirm")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    if args.command == "reset" and args.confirm != "RESET":
        print("Reset requires exact confirmation: reset --confirm RESET", file=sys.stderr)
        return 2
    try:
        config = load_config()
        if args.command == "init":
            _initialize(config, renew=args.renew_certificate)
            print("Lab initialized. Demo accounts: bob/BobDemo!2026, alice/AliceDemo!2026, admin/AdminDemo!2026.")
        elif args.command == "serve":
            with _graceful_sigterm():
                _serve(config)
        elif args.command == "reset":
            _reset(config)
            print("Lab data reset; existing key files preserved.")
        else:
            keys, _ = _initialize(config)
            print(json.dumps(analyze_pcap(config, keys, args.path), sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Lab error: {exc}", file=sys.stderr)
        return 1

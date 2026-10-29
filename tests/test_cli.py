"""CLI lifecycle tests use temporary data and injected listeners: no real ports."""

from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from security_lab import cli
from security_lab.crypto import open_record
from security_lab.db import connect, transaction
from security_lab.identity import load_or_create_keys
from security_lab.records import save_record


BOB_ID = "00000000000000000000000000000001"
ALICE_ID = "00000000000000000000000000000002"


@pytest.fixture
def configured(config, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: config, raising=False)
    return config


def rows(config, table):
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]


def key_bytes(config):
    return {path.name: path.read_bytes() for path in (config.data_dir / "keys").iterdir()}


def test_init_seeds_fixed_ids_valid_roles_scrypt_and_encrypted_records(configured):
    assert cli.main(["init"]) == 0
    users = {row["username"]: row for row in rows(configured, "users")}
    assert set(users) == {"bob", "alice", "admin"}
    for username, role, password in (
        ("bob", "user", "BobDemo!2026"),
        ("alice", "user", "AliceDemo!2026"),
        ("admin", "admin", "AdminDemo!2026"),
    ):
        assert users[username]["role"] == role
        assert users[username]["password_hash"].startswith("scrypt:")
        assert check_password_hash(users[username]["password_hash"], password)
    keys = load_or_create_keys(configured)
    records = {row["id"]: row for row in rows(configured, "records")}
    assert set(records) == {BOB_ID, ALICE_ID}
    versions = rows(configured, "record_versions")
    assert {(row["id"], row["version"]) for row in versions} == {
        (BOB_ID, 1), (ALICE_ID, 1),
    }
    snapshots = {row["id"]: row for row in versions}
    for record_id, owner, title in ((BOB_ID, "bob", "Bob's record"), (ALICE_ID, "alice", "Alice's record")):
        row = records[record_id]
        snapshot = snapshots[record_id]
        assert row["owner"] == owner and row["version"] == 1
        assert snapshot["owner"] == owner and snapshot["version"] == 1
        assert row["envelope_schema"] == snapshot["envelope_schema"] == 2
        image_columns = (
            "image_nonce", "image_ciphertext", "image_mime", "image_size",
            "image_plain_sha256", "image_cipher_sha256", "image_encrypt_ns", "image_hash_ns",
        )
        assert all(row[field] is None and snapshot[field] is None for field in image_columns)
        for field in ("nonce_b64", "ciphertext_b64", "sha256_hex", "signature_b64"):
            assert snapshot[field] == row[field]
        plaintext = open_record(keys, row)
        assert plaintext["title"] == title
        assert plaintext["body"].strip()
        assert open_record(keys, snapshot) == plaintext
    assert keys.storage_session_secret != keys.console_session_secret
    assert (configured.data_dir / "captures").is_dir()
    assert not (configured.data_dir / "server.pid").exists()


def test_init_twice_preserves_edited_records_credentials_evidence_and_keys(configured):
    assert cli.main(["init"]) == 0
    keys = load_or_create_keys(configured)
    save_record(configured, keys, owner="bob", record_id=BOB_ID, title="Edited title",
                body="Existing data must survive initialization.", src_ip="127.0.0.1", session_ref="test-edit")
    changed_hash = generate_password_hash("ChangedDemo!2026", method="scrypt")
    with transaction(configured) as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE username='bob'", (changed_hash,))
        conn.execute("INSERT INTO blocks VALUES(?,?,?,?)", ("192.0.2.9", 1, "admin", "test block"))
    before = {table: rows(configured, table) for table in ("users", "records", "events", "blocks")}
    identities = key_bytes(configured)
    assert cli.main(["init"]) == 0
    assert {table: rows(configured, table) for table in before} == before
    assert key_bytes(configured) == identities
    assert open_record(keys, next(row for row in rows(configured, "records") if row["id"] == BOB_ID))["title"] == "Edited title"


def test_init_adds_only_missing_seed_and_does_not_replace_other_seed(configured):
    assert cli.main(["init"]) == 0
    bob = next(row for row in rows(configured, "records") if row["id"] == BOB_ID)
    with transaction(configured) as conn:
        conn.execute("DELETE FROM records WHERE id=?", (ALICE_ID,))
        conn.execute("DELETE FROM users WHERE username='alice'")
    assert cli.main(["init"]) == 0
    assert next(row for row in rows(configured, "records") if row["id"] == BOB_ID) == bob
    assert {row["id"] for row in rows(configured, "records")} == {BOB_ID, ALICE_ID}


def test_cli_explicit_certificate_renewal_preserves_app_keys_and_record(configured):
    assert cli.main(["init"]) == 0
    before = key_bytes(configured)
    record = rows(configured, "records")
    assert cli.main(["init", "--renew-certificate"]) == 0
    after = key_bytes(configured)
    assert after["server.crt"] != before["server.crt"]
    for name in ("aes.key", "signing.key", "storage-session.key", "console-session.key"):
        assert after[name] == before[name]
    assert rows(configured, "records") == record


class Listener:
    def __init__(self, host, port, app, kwargs):
        self.host, self.port, self.app, self.kwargs = host, port, app, kwargs
        self.running = False
        self.shutdown_calls = 0
        self.close_calls = 0

    def serve_forever(self):
        raise AssertionError("Test listeners must never execute a real serving loop")

    def shutdown(self):
        assert self.running, "Unstarted listener shutdown would deadlock"
        self.shutdown_calls += 1
        self.running = False

    def server_close(self):
        self.close_calls += 1


class FakeThread:
    def __init__(self, target, **kwargs):
        self.listener = target.__self__
        self.joined = False

    def start(self):
        self.listener.running = True

    def is_alive(self):
        return self.listener.running

    def join(self, timeout=None):
        self.joined = True


class FakeCapture:
    def __init__(self, config, keys):
        self.config, self.keys = config, keys
        self.starts = 0
        self.stops = 0
        self.state = "stopped"

    def start(self):
        self.starts += 1
        self.state = "running"

    def stop(self):
        self.stops += 1
        self.state = "stopped"

    def health(self):
        return {"state": self.state}


@pytest.fixture
def lifecycle(monkeypatch, configured):
    listeners, captures, threads = [], [], []

    def server_factory(host, port, app, **kwargs):
        marker = json.loads((configured.data_dir / "server.pid").read_text())
        assert isinstance(marker["pid"], int) and marker["pid"] > 0
        assert isinstance(marker["started_at_us"], int) and marker["started_at_us"] > 0
        assert len(rows(configured, "records")) == 2
        listener = Listener(host, port, app, kwargs)
        listeners.append(listener)
        return listener

    def thread_factory(*args, **kwargs):
        thread = FakeThread(*args, **kwargs)
        threads.append(thread)
        return thread

    def capture_factory(config, keys):
        capture = FakeCapture(config, keys)
        captures.append(capture)
        return capture

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "make_server", server_factory, raising=False)
    monkeypatch.setattr(cli, "Thread", thread_factory, raising=False)
    monkeypatch.setattr(cli, "CaptureWorker", capture_factory, raising=False)
    monkeypatch.setattr(cli, "_wait_for_shutdown", interrupted, raising=False)
    return listeners, captures, threads


def test_serve_uses_two_threaded_https_factories_distinct_ports_and_secrets_then_closes(configured, lifecycle):
    listeners, captures, threads = lifecycle
    assert cli.main(["serve"]) == 0
    assert [listener.port for listener in listeners] == [configured.storage_port, configured.console_port]
    assert all(listener.host == configured.bind_host for listener in listeners)
    expected = (str(configured.data_dir / "keys/server.crt"), str(configured.data_dir / "keys/server.key"))
    assert all(listener.kwargs["threaded"] is True for listener in listeners)
    assert all(listener.kwargs["ssl_context"] == expected for listener in listeners)
    storage, console = [listener.app for listener in listeners]
    assert storage.secret_key != console.secret_key
    assert storage.config["SESSION_COOKIE_NAME"] == "storage_session"
    assert console.config["SESSION_COOKIE_NAME"] == "console_session"
    assert all(not app.debug for app in (storage, console))
    assert all(listener.shutdown_calls == 1 and listener.close_calls >= 1 for listener in listeners)
    assert all(thread.joined for thread in threads)
    assert captures == []
    assert not (configured.data_dir / "server.pid").exists()
    status = rows(configured, "status")
    health = json.loads(next(row["value_json"] for row in status if row["key"] == "capture"))
    assert health["state"] == "degraded" and "interface" in health["error"].lower()


def test_serve_starts_and_stops_only_its_configured_capture(configured, lifecycle, monkeypatch):
    active = replace(configured, capture_interface="test-interface")
    monkeypatch.setattr(cli, "load_config", lambda: active)
    listeners, captures, threads = lifecycle
    assert cli.main(["serve"]) == 0
    assert len(captures) == 1
    assert captures[0].config == active
    assert captures[0].starts == captures[0].stops == 1
    assert all(listener.shutdown_calls == 1 for listener in listeners)


def test_second_bind_failure_closes_first_without_unstarted_shutdown(configured, lifecycle, monkeypatch):
    listeners, captures, threads = lifecycle
    original = cli.make_server

    def fail_second(*args, **kwargs):
        if listeners:
            raise OSError("second bind unavailable")
        return original(*args, **kwargs)

    monkeypatch.setattr(cli, "make_server", fail_second)
    assert cli.main(["serve"]) != 0
    assert len(listeners) == 1
    assert listeners[0].close_calls >= 1
    assert listeners[0].shutdown_calls == 0
    assert not (configured.data_dir / "server.pid").exists()


def test_serve_does_not_remove_a_replaced_marker(configured, lifecycle, monkeypatch):
    replacement = '{"pid":999999,"started_at_us":1}'

    def replace_then_interrupt(*args, **kwargs):
        (configured.data_dir / "server.pid").write_text(replacement)
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_wait_for_shutdown", replace_then_interrupt)
    assert cli.main(["serve"]) == 0
    assert (configured.data_dir / "server.pid").read_text() == replacement


@pytest.mark.parametrize("command", [["serve"], ["reset", "--confirm", "RESET"]])
@pytest.mark.parametrize("contents", ['{"pid":123,"started_at_us":1}', "invalid marker"])
def test_existing_marker_refuses_without_data_changes(configured, command, contents, capsys):
    assert cli.main(["init"]) == 0
    identities = key_bytes(configured)
    records = rows(configured, "records")
    marker = configured.data_dir / "server.pid"
    marker.write_text(contents)
    assert cli.main(command) != 0
    assert marker.read_text() == contents
    assert key_bytes(configured) == identities
    assert rows(configured, "records") == records
    output = capsys.readouterr()
    assert "server.pid" in output.err
    assert "inspect" in output.err.lower() and "stale" in output.err.lower()


def test_analyze_pcap_delegates_offline_without_listener_or_capture(configured, monkeypatch, tmp_path, capsys):
    source = tmp_path / "provided.pcapng"
    source.write_bytes(b"synthetic capture passed to fake decoder")
    seen = []

    def analyze(config, keys, path):
        seen.append((config, keys, path))
        return {"domain": "offline:" + "a" * 64, "events": 4, "alerts": 1}

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline analysis must not start live listeners/capture")

    monkeypatch.setattr(cli, "analyze_pcap", analyze, raising=False)
    monkeypatch.setattr(cli, "make_server", forbidden, raising=False)
    monkeypatch.setattr(cli, "CaptureWorker", forbidden, raising=False)
    assert cli.main(["analyze-pcap", str(source)]) == 0
    assert len(seen) == 1 and seen[0][0] == configured and Path(seen[0][2]) == source
    assert seen[0][1].aes_key == load_or_create_keys(configured).aes_key
    assert "offline:" in capsys.readouterr().out
    assert not (configured.data_dir / "server.pid").exists()


@pytest.mark.parametrize("arguments", [["reset"], ["reset", "--confirm", "reset"], ["reset", "--confirm", "RESET "]])
def test_reset_without_exact_confirmation_has_no_side_effects(configured, arguments):
    assert cli.main(["init"]) == 0
    before = {table: rows(configured, table) for table in ("users", "records", "events", "blocks")}
    identities = key_bytes(configured)
    capture = configured.data_dir / "captures/keep.pcapng"
    capture.write_bytes(b"keep")
    assert cli.main(arguments) != 0
    assert {table: rows(configured, table) for table in before} == before
    assert key_bytes(configured) == identities and capture.read_bytes() == b"keep"
    assert not (configured.data_dir / "server.pid").exists()


def test_explicit_reset_clears_data_capture_blocks_but_preserves_all_key_files(configured):
    assert cli.main(["init"]) == 0
    identities = key_bytes(configured)
    keys = load_or_create_keys(configured)
    save_record(configured, keys, owner="bob", record_id=BOB_ID, title="Changed", body="Changed",
                src_ip="127.0.0.1", session_ref="test-reset")
    with transaction(configured) as conn:
        conn.execute("INSERT INTO blocks VALUES(?,?,?,?)", ("192.0.2.12", 1, "admin", "reset test"))
    capture = configured.data_dir / "captures/nested/old.pcapng"
    capture.parent.mkdir()
    capture.write_bytes(b"old capture")
    unrelated = configured.data_dir / "notes.txt"
    unrelated.write_text("must survive")
    assert cli.main(["reset", "--confirm", "RESET"]) == 0
    assert key_bytes(configured) == identities
    assert rows(configured, "blocks") == [] and rows(configured, "events") == []
    records = {row["id"]: row for row in rows(configured, "records")}
    assert set(records) == {BOB_ID, ALICE_ID} and records[BOB_ID]["version"] == 1
    assert open_record(keys, records[BOB_ID])["title"] == "Bob's record"
    assert not capture.exists() and (configured.data_dir / "captures").is_dir()
    assert unrelated.read_text() == "must survive"
    assert not (configured.data_dir / "server.pid").exists()


@pytest.mark.parametrize("relative", [".", "..", ".git", "security_lab", "tests", "docs", "../Project", "../Project/data"])
def test_reset_refuses_checkout_ancestors_code_and_read_only_reference(configured, monkeypatch, relative):
    repository = Path(cli.__file__).resolve().parent.parent
    unsafe = (repository / relative).resolve()
    monkeypatch.setattr(cli, "load_config", lambda: replace(configured, data_dir=unsafe))
    assert cli.main(["reset", "--confirm", "RESET"]) != 0


def test_reset_refuses_filesystem_root(configured, monkeypatch):
    filesystem_root = Path(configured.data_dir.anchor)
    monkeypatch.setattr(cli, "load_config", lambda: replace(configured, data_dir=filesystem_root))
    assert cli.main(["reset", "--confirm", "RESET"]) != 0


def test_reset_preflights_all_targets_before_removing_database(configured):
    assert cli.main(["init"]) == 0
    before = (configured.data_dir / "lab.sqlite3").read_bytes()
    identities = key_bytes(configured)
    # An unexpected sidecar directory must abort before the first DB unlink.
    bad_sidecar = configured.data_dir / "lab.sqlite3-wal"
    bad_sidecar.mkdir()
    (bad_sidecar / "sentinel").write_text("must survive")
    assert cli.main(["reset", "--confirm", "RESET"]) != 0
    assert (configured.data_dir / "lab.sqlite3").read_bytes() == before
    assert (bad_sidecar / "sentinel").read_text() == "must survive"
    assert key_bytes(configured) == identities


def test_reset_rejects_capture_link_escape_before_deleting_database(configured, tmp_path):
    assert cli.main(["init"]) == 0
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("outside")
    link = configured.data_dir / "captures/escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating directory links is unavailable on this machine")
    before = (configured.data_dir / "lab.sqlite3").read_bytes()
    assert cli.main(["reset", "--confirm", "RESET"]) != 0
    assert (configured.data_dir / "lab.sqlite3").read_bytes() == before
    assert (outside / "sentinel").read_text() == "outside" and link.is_symlink()


def test_sigterm_uses_owned_shutdown_and_restores_previous_handler(configured, lifecycle, monkeypatch):
    import signal

    active = replace(configured, capture_interface="test-interface")
    monkeypatch.setattr(cli, "load_config", lambda: active)
    previous = object()
    current = {"handler": previous}
    registrations = []

    def register(signum, handler):
        assert signum == signal.SIGTERM
        old = current["handler"]
        current["handler"] = handler
        registrations.append(handler)
        return old

    monkeypatch.setattr(signal, "signal", register)
    monkeypatch.setattr(signal, "getsignal", lambda signum: current["handler"])

    def terminate(*args, **kwargs):
        handler = current["handler"]
        assert callable(handler), "Serve must install a SIGTERM handler before waiting"
        handler(signal.SIGTERM, None)
        pytest.fail("SIGTERM must interrupt serving and enter owned-resource cleanup")

    monkeypatch.setattr(cli, "_wait_for_shutdown", terminate)
    listeners, captures, threads = lifecycle
    assert cli.main(["serve"]) == 0
    assert registrations and callable(registrations[0])
    assert registrations[-1] is previous and current["handler"] is previous
    assert all(listener.shutdown_calls == 1 and listener.close_calls >= 1 for listener in listeners)
    assert all(thread.joined for thread in threads)
    assert len(captures) == 1 and captures[0].starts == captures[0].stops == 1
    assert not (configured.data_dir / "server.pid").exists()

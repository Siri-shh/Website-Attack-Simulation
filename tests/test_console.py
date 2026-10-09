"""T11 contracts for the separate admin console and public snapshots."""

from contextlib import closing
from pathlib import Path
import re

import pytest
from werkzeug.security import generate_password_hash

from security_lab.audit import append_app_event, verify_app_event
from security_lab.console import create_console_app, snapshot
from security_lab.db import connect, transaction
from security_lab.storage import create_storage_app


def _csrf(client, path="/login"):
    response = client.get(path, base_url="https://localhost")
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.data.decode("utf-8")
    return match.group(1).decode("ascii")


def _seed(config):
    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES(?,?,?,?)",
            [
                ("bob", "user", generate_password_hash("BobPass!2026", method="scrypt"), 1),
                ("admin", "admin", generate_password_hash("AdminPass!2026", method="scrypt"), 2),
            ],
        )


@pytest.fixture
def console_app(config, keys):
    from jinja2 import DictLoader

    _seed(config)
    app = create_console_app(config, keys)
    app.config.update(TESTING=True)
    app.jinja_loader = DictLoader({
        "login.html": '<form method="post"><input name="csrf_token" value="{{ csrf_token() }}"></form>',
        "console/dashboard.html": '<input name="csrf_token" value="{{ csrf_token }}">{{ snapshot.domain }}',
    })
    return app


def _login(client, username="admin", password="AdminPass!2026", peer="192.0.2.10"):
    token = _csrf(client)
    return client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": token, "username": username, "password": password},
        environ_overrides={"REMOTE_ADDR": peer}, follow_redirects=False,
    )


def _events(config):
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY seq")]


def test_admin_can_view_console_but_storage_user_cannot_authenticate_or_reuse_cookie(
    config, keys, console_app
):
    console = console_app.test_client()
    assert console.get("/", base_url="https://localhost").status_code in (302, 303)
    assert console.get("/api/snapshot", base_url="https://localhost").status_code in (302, 303)

    denied = _login(console, "bob", "BobPass!2026")
    assert denied.status_code == 401
    assert console.get("/", base_url="https://localhost").status_code in (302, 303)

    storage = create_storage_app(config, keys).test_client()
    storage_login = _login(storage, "bob", "BobPass!2026")
    assert storage_login.status_code == 303
    storage_cookie = storage.get_cookie("storage_session", domain="localhost")
    assert storage_cookie is not None
    console.set_cookie("console_session", storage_cookie.value, domain="localhost")
    assert console.get("/", base_url="https://localhost").status_code in (302, 303)

    authorized = _login(console)
    assert authorized.status_code == 303
    assert console.get("/", base_url="https://localhost").status_code == 200
    api = console.get("/api/snapshot", base_url="https://localhost")
    assert api.status_code == 200
    assert api.json["domain"] == "live"


def test_manual_block_normalizes_persists_and_audits_admin_peer_and_target(
    config, keys, console_app
):
    client = console_app.test_client()
    assert _login(client).status_code == 303
    csrf = _csrf(client, "/")
    response = client.post(
        "/blocks", base_url="https://localhost",
        data={"ip": "::ffff:192.0.2.77", "reason": "reviewed evidence", "csrf_token": csrf},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10", "HTTP_X_FORWARDED_FOR": "198.51.100.1"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    snap = snapshot(config, keys)
    assert snap["blocks"] == [{
        "ip": "192.0.2.77", "created_by": "admin", "reason": "reviewed evidence",
        "created_at_us": snap["blocks"][0]["created_at_us"],
    }]
    row = next(event for event in reversed(_events(config)) if event["kind"] == "admin_block")
    assert row["src_ip"] == "192.0.2.10"
    assert row["dst_ip"] == "192.0.2.77"
    assert row["username"] == "admin"
    assert verify_app_event(keys, row)


@pytest.mark.parametrize("form", [
    {"ip": "192.0.2.77", "reason": "manual"},
    {"ip": "192.0.2.77", "reason": "manual", "csrf_token": "wrong"},
])
def test_block_requires_valid_csrf(config, keys, console_app, form):
    client = console_app.test_client()
    assert _login(client).status_code == 303
    before = len(_events(config))
    response = client.post("/blocks", base_url="https://localhost", data=form)
    assert response.status_code == 400
    assert len(_events(config)) == before
    assert snapshot(config, keys)["blocks"] == []


def test_unblock_requires_csrf_removes_persistent_block_and_audits_target(
    config, keys, console_app
):
    client = console_app.test_client()
    assert _login(client).status_code == 303
    token = _csrf(client, "/")
    assert client.post(
        "/blocks", base_url="https://localhost",
        data={"ip": "192.0.2.77", "reason": "reviewed", "csrf_token": token},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    ).status_code == 303
    before = len(_events(config))
    assert client.post(
        "/blocks/192.0.2.77/remove", base_url="https://localhost", data={},
    ).status_code == 400
    assert len(_events(config)) == before
    token = _csrf(client, "/")
    result = client.post(
        "/blocks/192.0.2.77/remove", base_url="https://localhost",
        data={"csrf_token": token}, environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
        follow_redirects=False,
    )
    assert result.status_code == 303
    assert snapshot(config, keys)["blocks"] == []
    row = next(event for event in reversed(_events(config)) if event["kind"] == "admin_unblock")
    assert row["src_ip"] == "192.0.2.10"
    assert row["dst_ip"] == "192.0.2.77"
    assert verify_app_event(keys, row)


def test_existing_bob_session_is_blocked_ignoring_xff_then_recovers_after_unblock(
    config, keys, console_app
):
    storage_client = create_storage_app(config, keys).test_client()
    assert _login(storage_client, "bob", "BobPass!2026", "192.0.2.77").status_code == 303

    admin = console_app.test_client()
    assert _login(admin).status_code == 303
    token = _csrf(admin, "/")
    assert admin.post(
        "/blocks", base_url="https://localhost",
        data={"ip": "192.0.2.77", "reason": "reviewed", "csrf_token": token},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    ).status_code == 303
    denied = storage_client.get(
        "/", base_url="https://localhost",
        environ_overrides={"REMOTE_ADDR": "192.0.2.77", "HTTP_X_FORWARDED_FOR": "203.0.113.8"},
    )
    assert denied.status_code == 403
    blocked = next(event for event in reversed(_events(config)) if event["kind"] == "blocked_request")
    assert blocked["src_ip"] == "192.0.2.77"
    assert blocked["src_ip"] != "203.0.113.8"

    token = _csrf(admin, "/")
    assert admin.post(
        "/blocks/192.0.2.77/remove", base_url="https://localhost",
        data={"csrf_token": token}, environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    ).status_code == 303
    restored = storage_client.get(
        "/", base_url="https://localhost", environ_overrides={"REMOTE_ADDR": "192.0.2.77"},
    )
    assert restored.status_code == 200


def test_snapshot_is_allowlisted_bounded_and_live_is_default(config, keys):
    _seed(config)
    with transaction(config) as conn:
        for i in range(105):
            append_app_event(conn, keys, {
                "domain": "live", "event_id": f"{i:032x}", "time_us": i + 1,
                "kind": "record_read", "src_ip": "192.0.2.10", "dst_ip": "127.0.0.1",
                "dst_port": 8443, "username": "bob", "session_ref": "opaque-ref",
                "record_id": f"{i:032x}", "outcome": "record_read",
            })
        append_app_event(conn, keys, {
            "domain": "live", "event_id": "f" * 32, "time_us": 1000,
            "kind": "record_read", "src_ip": "192.0.2.10", "dst_ip": "127.0.0.1",
            "dst_port": 8443, "username": "bob", "session_ref": "opaque-ref",
            "record_id": "f" * 32, "outcome": "record_read",
        })
        conn.execute(
            "INSERT INTO events(domain,event_id,time_us,kind,src_ip,dst_ip,dst_port,username,session_ref,record_id,outcome,payload_json,signature_b64,capture_id,frame_number) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("offline:deadbeef", "packet-1", 2000, "connection_attempt", "192.0.2.20", "127.0.0.1", 8443, None, None, None, "observed", "{}", None, "capture-1", 1),
        )

    result = snapshot(config, keys)
    assert result["domain"] == "live"
    assert result["domains"] == ["live", "offline:deadbeef"]
    assert len(result["events"]) == 100
    assert result["events"][0]["time_us"] == 1000
    assert all(event["signature_valid"] is True for event in result["events"])
    assert not ({"payload_json", "signature_b64", "private_key", "plaintext", "password_hash"}
                & set().union(*(event.keys() for event in result["events"])))
    packet = snapshot(config, keys, "offline:deadbeef")["events"]
    assert len(packet) == 1
    assert packet[0]["signature_valid"] is None
    assert packet[0]["domain"] == "offline:deadbeef"

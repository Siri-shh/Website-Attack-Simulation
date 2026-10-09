"""Packaged live admin console page contracts for T12."""

from pathlib import Path
import re

import pytest
from jinja2 import FileSystemLoader

from security_lab.audit import append_app_event
from security_lab.db import transaction
from security_lab.console import create_console_app
from werkzeug.security import generate_password_hash


_TEMPLATE_ROOT = Path(__file__).parents[1] / "security_lab" / "templates"
_STATIC_ROOT = Path(__file__).parents[1] / "security_lab" / "static"


@pytest.fixture
def real_console_client(config, keys):
    """Build the independent console with packaged dashboard templates."""
    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES(?,?,?,?)",
            [
                ("bob", "user", generate_password_hash("BobPass!2026", method="scrypt"), 1),
                ("admin", "admin", generate_password_hash("AdminPass!2026", method="scrypt"), 2),
            ],
        )
    console_app = create_console_app(config, keys)
    console_app.config.update(TESTING=True)
    console_app.jinja_loader = FileSystemLoader(str(_TEMPLATE_ROOT))
    console_app.jinja_env.cache.clear()
    return console_app.test_client()


def _csrf(client, path="/login"):
    response = client.get(path, base_url="https://localhost")
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.get_data(as_text=True)
    return match.group(1).decode("ascii")


def _login(client, username="admin", password="AdminPass!2026"):
    token = _csrf(client)
    return client.post(
        "/login",
        base_url="https://localhost",
        data={"csrf_token": token, "username": username, "password": password},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
        follow_redirects=False,
    )


def test_dashboard_and_snapshot_are_admin_only(real_console_client):
    assert real_console_client.get("/", base_url="https://localhost").status_code in (302, 303)
    assert real_console_client.get(
        "/api/snapshot", base_url="https://localhost"
    ).status_code in (302, 303)

    denied = _login(real_console_client, "bob", "BobPass!2026")
    assert denied.status_code == 401
    assert real_console_client.get("/", base_url="https://localhost").status_code in (302, 303)


def test_admin_dashboard_exposes_csrf_protected_block_forms(real_console_client):
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/")
    response = real_console_client.post(
        "/blocks", base_url="https://localhost",
        data={"ip": "192.0.2.77", "reason": "reviewed", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = real_console_client.get("/", base_url="https://localhost")
    assert page.status_code == 200
    html = page.get_data(as_text=True)

    assert re.search(r'<form(?=[^>]*action="/blocks")(?=[^>]*method="post")[^>]*>', html, re.I)
    assert 'name="csrf_token"' in html and 'value="' in html
    assert re.search(r'<input[^>]+name="ip"', html)
    assert re.search(r'<input[^>]+name="reason"', html)
    assert re.search(r'<form(?=[^>]*action="/blocks/[^"]+/remove")(?=[^>]*method="post")[^>]*>', html, re.I)
    assert re.search(r'name="domain"', html)


def test_dashboard_labels_account_context_and_encrypted_network_metadata(real_console_client):
    assert _login(real_console_client).status_code == 303
    page = real_console_client.get("/", base_url="https://localhost")
    assert page.status_code == 200
    html = page.get_data(as_text=True).lower()

    assert "attempted" in html and "authenticated" in html
    assert "attacker identity" in html
    assert "encrypted" in html and "metadata" in html


def test_empty_and_degraded_capture_states_are_visible(real_console_client, config):
    assert _login(real_console_client).status_code == 303
    with transaction(config) as conn:
        conn.execute(
            "INSERT INTO status(key,value_json) VALUES('capture',?)",
            ('{"state":"degraded","error":"adapter unavailable"}',),
        )

    page = real_console_client.get("/", base_url="https://localhost")
    assert page.status_code == 200
    html = page.get_data(as_text=True).lower()
    assert "degraded" in html
    assert "adapter unavailable" in html
    assert re.search(r"(no|empty|none).*(event|alert|block)|(event|alert|block).*(no|empty|none)", html)


def test_malicious_username_is_escaped_and_dynamic_rendering_uses_text_content(
    real_console_client, config, keys
):
    assert _login(real_console_client).status_code == 303
    hostile = '<img src=x onerror=alert(1)>'
    with transaction(config) as conn:
        append_app_event(conn, keys, {
            "domain": "live", "event_id": "a" * 32, "time_us": 10,
            "kind": "login_failure", "src_ip": "192.0.2.77", "dst_ip": "127.0.0.1",
            "dst_port": 8443, "username": hostile, "session_ref": None,
            "record_id": None, "outcome": "denied",
        })

    page = real_console_client.get("/", base_url="https://localhost")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert hostile not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html

    script = (_STATIC_ROOT / "console.js").read_text(encoding="utf-8")
    assert "textContent" in script
    assert "innerHTML" not in script

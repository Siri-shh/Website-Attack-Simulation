"""Packaged live admin console page contracts for T12."""

from pathlib import Path
import re

import pytest
from jinja2 import FileSystemLoader

from security_lab.audit import append_app_event
from security_lab.db import transaction
from security_lab.console import create_console_app
from security_lab.config import format_ist
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
            ('{"state":"degraded","error":"adapter unavailable","last_packet_at_us":1000001}',),
        )

    page = real_console_client.get("/", base_url="https://localhost")
    assert page.status_code == 200
    html = page.get_data(as_text=True).lower()
    assert "degraded" in html
    assert "adapter unavailable" in html
    assert "last packet (ist)" in html
    assert "1970-01-01t05:30:01.000001+05:30" in html
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
    assert "Time (IST)" in html
    assert format_ist(10) in html

    script = (_STATIC_ROOT / "console.js").read_text(encoding="utf-8")
    assert "textContent" in script
    assert "innerHTML" not in script


def _analysis_result(name):
    if name == "aes_gcm":
        return {
            "input_bytes": 4, "warmup_pairs": 20, "timed_encryptions": 1000,
            "timed_decryptions": 1000, "ciphertext_bytes": 20, "tag_bytes": 16,
            "sample_nonce_hex": "00" * 12, "sample_ciphertext_hex": "11" * 20,
            "recovered_text": "demo", "plaintext_matches": True,
            "encryption_timing_ns": {"median": 1.0, "p95": 2},
            "decryption_timing_ns": {"median": 3.0, "p95": 4},
        }
    if name == "sha256":
        panel = {"budget": 2, "attempts": 2, "elapsed_ns": 7, "found": False, "candidate_hex": None}
        return {
            "input_bytes": 4, "target_digest_hex": "ab" * 32,
            "preimage": panel, "second_preimage": panel,
            "collision": {**panel, "first_candidate_hex": None, "second_candidate_hex": None, "digest_hex": None},
        }
    avalanche = {
        "mean_changed_bits": 64.0, "min_changed_bits": 50, "max_changed_bits": 78,
        "mean_changed_percent": 50.0, "min_changed_percent": 39.0, "max_changed_percent": 61.0,
    }
    return {
        "input_bytes": 4, "block_hex": "00" * 16, "keys_tested": 32,
        "baseline_encryptions": 32, "plaintext_comparisons": 4096,
        "key_comparisons": 8192, "total_encryptions": 12320,
        "plaintext_avalanche": avalanche, "key_avalanche": avalanche,
        "sac": {"flip_percentages": [[50.0] * 128 for _ in range(128)],
                "mean_abs_deviation_percentage_points": 0.0,
                "min_flip_percent": 50.0, "max_flip_percent": 50.0},
    }


def test_analysis_page_requires_admin_and_is_not_cached(real_console_client):
    response = real_console_client.get("/analysis", base_url="https://localhost")
    assert response.status_code in (302, 303)
    assert response.headers["Cache-Control"] == "no-store"

    with real_console_client.session_transaction() as state:
        state["username"] = "bob"
        state["role"] = "user"
        state["session_ref"] = "test-session"
    response = real_console_client.get("/analysis", base_url="https://localhost")
    assert response.status_code in (302, 303)
    assert response.headers["Cache-Control"] == "no-store"

    _login(real_console_client)
    response = real_console_client.get("/analysis", base_url="https://localhost")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert b"name=\"input_text\"" in response.data
    assert b"aes-gcm" in response.data and b"sha256" in response.data and b"aes-primitive" in response.data
    assert b"console.js" not in response.data


def test_dashboard_links_to_analysis(real_console_client):
    _login(real_console_client)
    response = real_console_client.get("/", base_url="https://localhost")
    assert response.status_code == 200
    assert b'href="/analysis"' in response.data


def test_each_analysis_action_requires_csrf_and_uses_default_sample(real_console_client, monkeypatch):
    from security_lab import console

    calls = []
    for action, attr in (("aes-gcm", "aes_gcm_analysis"), ("sha256", "sha256_analysis"),
                         ("aes-primitive", "aes_primitive_analysis")):
        def stub(data, *, _action=action):
            calls.append((_action, data))
            return _analysis_result(_action.replace("-", "_").replace("aes_primitive", "aes_primitive"))
        monkeypatch.setattr(console, attr, stub)

    _login(real_console_client)
    for action in ("aes-gcm", "sha256", "aes-primitive"):
        missing = real_console_client.post(f"/analysis/{action}", data={}, base_url="https://localhost")
        assert missing.status_code == 400
        assert missing.headers["Cache-Control"] == "no-store"
        token = _csrf(real_console_client, "/analysis")
        response = real_console_client.post(
            f"/analysis/{action}", data={"csrf_token": token}, base_url="https://localhost"
        )
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
    assert [action for action, _ in calls] == ["aes-gcm", "sha256", "aes-primitive"]
    assert all(data == b"Cryptography analysis sample" for _, data in calls)


def test_analysis_enforces_utf8_byte_limit_without_echoing_oversized_text(real_console_client, monkeypatch):
    from security_lab import console

    seen = []
    monkeypatch.setattr(console, "sha256_analysis", lambda data: seen.append(data) or _analysis_result("sha256"))
    _login(real_console_client)
    token = _csrf(real_console_client, "/analysis")
    exact = "é" * 5120
    accepted = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token, "input_text": exact}, base_url="https://localhost"
    )
    assert accepted.status_code == 200
    assert seen == [exact.encode("utf-8")]
    too_large = "é" * 5121
    rejected = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token, "input_text": too_large}, base_url="https://localhost"
    )
    assert rejected.status_code == 400
    assert rejected.headers["Cache-Control"] == "no-store"
    assert too_large.encode() not in rejected.data


def test_analysis_escapes_user_text_and_shows_result_panels(real_console_client, monkeypatch):
    from security_lab import console

    monkeypatch.setattr(console, "aes_gcm_analysis", lambda data: {
        **_analysis_result("aes_gcm"), "recovered_text": "<script>alert(1)</script>"
    })
    monkeypatch.setattr(console, "sha256_analysis", lambda data: _analysis_result("sha256"))
    monkeypatch.setattr(console, "aes_primitive_analysis", lambda data: _analysis_result("aes_primitive"))
    _login(real_console_client)
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/aes-gcm", data={"csrf_token": token, "input_text": "<b>hello</b>"},
        base_url="https://localhost",
    )
    assert response.status_code == 200
    assert b"&lt;b&gt;hello&lt;/b&gt;" in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    token = _csrf(real_console_client, "/analysis")
    sha_response = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token}, base_url="https://localhost"
    )
    assert b"no-match result in these bounded searches is expected and is not proof" in sha_response.data
    primitive_response = real_console_client.post(
        "/analysis/aes-primitive", data={"csrf_token": token}, base_url="https://localhost"
    )
    assert b"ECB is unsuitable for protecting stored messages" in primitive_response.data
    assert b"illustration of diffusion" in primitive_response.data
    assert b"do not prove confusion" in primitive_response.data


def test_analysis_posts_do_not_add_database_events(real_console_client, config, monkeypatch):
    from security_lab import console
    from security_lab.db import transaction

    monkeypatch.setattr(console, "aes_gcm_analysis", lambda data: _analysis_result("aes_gcm"))
    monkeypatch.setattr(console, "sha256_analysis", lambda data: _analysis_result("sha256"))
    monkeypatch.setattr(console, "aes_primitive_analysis", lambda data: _analysis_result("aes_primitive"))
    _login(real_console_client)

    with transaction(config) as conn:
        before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    token = _csrf(real_console_client, "/analysis")
    for action in ("aes-gcm", "sha256", "aes-primitive"):
        response = real_console_client.post(
            f"/analysis/{action}", data={"csrf_token": token}, base_url="https://localhost"
        )
        assert response.status_code == 200
    with transaction(config) as conn:
        after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert after == before

"""Packaged live admin console page contracts for T12."""

from pathlib import Path
import re

import pytest
from jinja2 import FileSystemLoader

from security_lab.audit import append_app_event
from security_lab.db import transaction
from security_lab.console import create_console_app
from security_lab.config import format_ist
from security_lab.storage import create_storage_app
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


def test_login_pages_distinguish_storage_countdown_and_admin_identity(config, keys, monkeypatch):
    from security_lab import auth

    now_us = 1_000_000_000
    monkeypatch.setattr(auth, "utc_us", lambda: now_us)
    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES(?,?,?,?)",
            [
                ("bob", "user", generate_password_hash("BobPass!2026", method="scrypt"), 1),
                ("admin", "admin", generate_password_hash("AdminPass!2026", method="scrypt"), 2),
            ],
        )
    storage_app = create_storage_app(config, keys)
    storage_app.config.update(TESTING=True)
    storage_app.jinja_loader = FileSystemLoader(str(_TEMPLATE_ROOT))
    storage_app.jinja_env.cache.clear()
    storage = storage_app.test_client()
    admin = create_console_app(config, keys)
    admin.config.update(TESTING=True)
    admin.jinja_loader = FileSystemLoader(str(_TEMPLATE_ROOT))
    admin.jinja_env.cache.clear()
    console = admin.test_client()

    storage_page = storage.get("/login", base_url="https://localhost")
    console_page = console.get("/login", base_url="https://localhost")
    assert storage_page.status_code == console_page.status_code == 200
    assert b"storage" in storage_page.data.lower()
    assert b"console" in console_page.data.lower() and b"admin" in console_page.data.lower()
    assert b'name="csrf_token"' in storage_page.data
    assert b'name="csrf_token"' in console_page.data

    with transaction(config) as conn:
        conn.execute(
            "INSERT INTO alerts(id,domain,rule,src_ip,username,session_ref,time_us,"
            "trigger_event_id,severity,summary,evidence_json,dedup_key) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("active-r2", "live", "R2", "192.0.2.77", "bob", None, now_us,
             "event-r2", "high", "Repeated failures", "{}", "active-r2"),
        )
    token = re.search(rb'name="csrf_token" value="([^"]+)"', storage_page.data).group(1)
    restricted = storage.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": token, "username": "bob", "password": "BobPass!2026"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.77"}, follow_redirects=False,
    )
    assert restricted.status_code == 429
    assert b"temporarily restricted" in restricted.data.lower()
    assert b"90 seconds" in restricted.data
    assert b'name="csrf_token"' in restricted.data


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
    def avalanche(comparisons):
        counts = [1, 2, 3, 4, 5, 6, 7, 8, 9, comparisons - 45]
        return {
            "mean_changed_bits": 64.0, "min_changed_bits": 50, "max_changed_bits": 78,
            "mean_changed_percent": 50.0, "min_changed_percent": 39.0, "max_changed_percent": 61.0,
            "distribution_10pct": [
                {"lower_percent": lower, "upper_percent": lower + 10, "count": count}
                for lower, count in zip(range(0, 100, 10), counts)
            ],
        }
    return {
        "input_bytes": 4, "block_hex": "00" * 16, "keys_tested": 32,
        "baseline_encryptions": 32, "plaintext_comparisons": 4096,
        "key_comparisons": 8192, "total_encryptions": 12320,
        "plaintext_avalanche": avalanche(4096), "key_avalanche": avalanche(8192),
        "hex_character_change": {"changed": 16, "total": 32, "percent": 50.0},
        "sac": {"flip_percentages": [[50.0] * 128 for _ in range(128)],
                "summary_16x16": [[50.0] * 16 for _ in range(16)],
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


def test_size_sweep_has_its_own_csrf_protected_post_form(real_console_client):
    assert _login(real_console_client).status_code == 303
    response = real_console_client.get("/analysis", base_url="https://localhost")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    form = re.search(
        r'<form(?=[^>]*method="post")(?=[^>]*action="/analysis/size-sweep")[^>]*>(.*?)</form>',
        html, re.I | re.S,
    )
    assert form
    assert 'name="csrf_token"' in form.group(1)
    assert re.search(r'<button[^>]*>[^<]*size sweep[^<]*</button>', form.group(1), re.I)


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


def test_size_sweep_post_requires_admin_csrf_and_passes_isolated_result(real_console_client, monkeypatch):
    from security_lab import console

    path = "/analysis/size-sweep"
    anonymous = real_console_client.post(path, base_url="https://localhost")
    assert anonymous.status_code in (302, 303)
    assert anonymous.headers["Cache-Control"] == "no-store"

    with real_console_client.session_transaction() as state:
        state["username"] = "bob"
        state["role"] = "user"
        state["session_ref"] = "test-session"
    user = real_console_client.post(path, base_url="https://localhost")
    assert user.status_code in (302, 303)
    assert user.headers["Cache-Control"] == "no-store"

    assert _login(real_console_client).status_code == 303
    missing_csrf = real_console_client.post(path, base_url="https://localhost")
    assert missing_csrf.status_code == 400
    assert missing_csrf.headers["Cache-Control"] == "no-store"

    marker = {
        "sizes": [128], "samples_per_size": 1,
        "points": [{"input_bytes": 128, **{
            operation: {"median_ns": 2_000, "p95_ns": 2_000, "mib_per_s": 61.03515625}
            for operation in ("aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify")
        }}],
    }
    calls = []
    monkeypatch.setattr(console, "benchmark_size_sweep", lambda *args, **kwargs: (
        calls.append((args, kwargs)) or marker
    ))
    original_render = console.render_template
    rendered = []

    def capture_render(template, **context):
        if template == "console/analysis.html":
            rendered.append(context)
        return original_render(template, **context)

    monkeypatch.setattr(console, "render_template", capture_render)
    monkeypatch.setattr(console, "connect", lambda *args, **kwargs: pytest.fail("analysis opened database"))
    monkeypatch.setattr(console, "transaction", lambda *args, **kwargs: pytest.fail("analysis wrote database"))
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(path, data={"csrf_token": token}, base_url="https://localhost")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert calls == [((), {})]
    assert rendered[-1]["result_type"] == "size-sweep"
    assert rendered[-1]["result"] is marker
    assert rendered[-1]["analysis_error"] is None


def test_size_sweep_renders_all_numeric_sizes_operations_and_units(real_console_client, monkeypatch):
    from security_lab import console

    sizes = [128, 1024, 10240, 102400, 1048576]
    operations = ("aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify")
    points = []
    for index, size in enumerate(sizes, start=1):
        points.append({"input_bytes": size, **{
            operation: {
                "median_ns": index * 1000,
                "p95_ns": index * 1500,
                "mib_per_s": round(size * 1_000_000_000 / (index * 1000 * 1_048_576), 6),
            }
            for operation in operations
        }})
    marker = {"sizes": sizes, "samples_per_size": 100, "points": points}
    monkeypatch.setattr(console, "benchmark_size_sweep", lambda: marker)
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/size-sweep", data={"csrf_token": token}, base_url="https://localhost"
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Size sweep measurements" in html
    assert "Input size (bytes)" in html
    assert "Input size is the row category" in html
    assert "horizontal bar length encodes median duration" in html
    assert "Median duration (ns)" in html and "p95 duration (ns)" in html
    assert "Throughput (MiB/s)" in html
    assert "throughput values are rounded to six decimal places" in html
    for size, point in zip(sizes, points):
        assert str(size) in html
        for operation in operations:
            result = point[operation]
            assert operation.replace("_", " ").lower() in html.lower()
            assert str(result["median_ns"]) in html
            assert str(result["p95_ns"]) in html
            assert str(result["mib_per_s"]) in html
    assert "100 samples per size" in html.lower()


def test_sha_search_graph_shows_numeric_attempts_elapsed_and_no_match_caveat(real_console_client, monkeypatch):
    from security_lab import console

    monkeypatch.setattr(console, "sha256_analysis", lambda data: _analysis_result("sha256"))
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token, "input_text": "temporary search input"},
        base_url="https://localhost",
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Bounded SHA-256 search measurements" in html
    assert "Attempts" in html and "Elapsed time (ns)" in html
    assert "2" in html and "7" in html
    assert "no match found" in html.lower()
    assert "not proof of resistance" in html.lower()


def test_aes_primitive_graph_exposes_50_percent_reference_hex_metric_and_full_matrix(
    real_console_client, monkeypatch,
):
    from security_lab import console

    monkeypatch.setattr(console, "aes_primitive_analysis", lambda data: _analysis_result("aes_primitive"))
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/aes-primitive", data={"csrf_token": token}, base_url="https://localhost"
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Changed output bits (%)" in html
    assert "50% reference" in html
    assert "Hex-character change for the same one-bit input flip" in html
    assert "16 of 32 hexadecimal characters" in html
    assert "50.0%" in html
    assert "16 × 16 SAC summary" in html
    assert "Show the complete 128 by 128 flip-percentage matrix" in html
    assert "ECB is unsuitable for protecting stored messages" in html


def test_aes_primitive_shows_two_ten_bin_distributions_with_counts_and_half_boundary(
    real_console_client, monkeypatch,
):
    from security_lab import console

    monkeypatch.setattr(console, "aes_primitive_analysis", lambda data: _analysis_result("aes_primitive"))
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/aes-primitive", data={"csrf_token": token}, base_url="https://localhost"
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Plaintext bit-change distribution" in html
    assert "Key bit-change distribution" in html
    assert html.count('class="distribution-chart"') == 2
    assert html.count('class="distribution-boundary"') == 2
    assert "0–10%" in html and "90–100%" in html
    assert "4096 comparisons" in html and "8192 comparisons" in html
    for lower in range(0, 100, 10):
        assert f"{lower}–{lower + 10}%" in html


def test_temporary_analysis_input_is_not_persisted(real_console_client, config, monkeypatch):
    from security_lab import console

    marker = "private-transient-input-7f31"
    monkeypatch.setattr(console, "sha256_analysis", lambda data: _analysis_result("sha256"))
    assert _login(real_console_client).status_code == 303
    with transaction(config) as conn:
        before = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("records", "record_versions", "events")}
    token = _csrf(real_console_client, "/analysis")
    response = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token, "input_text": marker},
        base_url="https://localhost",
    )

    assert response.status_code == 200
    assert marker in response.get_data(as_text=True)
    with transaction(config) as conn:
        after = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                 for table in ("records", "record_versions", "events")}
        event_json = " ".join(row[0] for row in conn.execute("SELECT payload_json FROM events"))
    assert after == before
    assert marker not in event_json


def test_console_analysis_chart_rules_have_dark_mode_contrast():
    css = (_STATIC_ROOT / "console.css").read_text(encoding="utf-8")
    dark_start = css.rfind("@media(prefers-color-scheme:dark)")
    assert dark_start >= 0
    dark_rules = css[dark_start:]
    assert ".transient-note" in dark_rules and "background:" in dark_rules
    assert re.search(
        r"\.chart-data-table thead th\s*\{[^}]*color:\s*#e6edf5[^}]*background:",
        dark_rules,
    )
    assert re.search(r"\.distribution-boundary\s*\{[^}]*color:\s*#842b2f", css)
    assert not re.search(r"\.distribution-boundary\s*\{[^}]*color:\s*#ffb4ad", dark_rules)


def test_analysis_numeric_tables_use_keyboard_scroll_regions_at_mobile_width(real_console_client, monkeypatch):
    from security_lab import console

    sizes = [128, 1024, 10240, 102400, 1048576]
    operations = ("aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify")
    sweep = {"sizes": sizes, "samples_per_size": 1, "points": [
        {"input_bytes": size, **{
            operation: {"median_ns": 1000, "p95_ns": 1200, "mib_per_s": 0.5}
            for operation in operations
        }}
        for size in sizes
    ]}
    monkeypatch.setattr(console, "benchmark_size_sweep", lambda: sweep)
    assert _login(real_console_client).status_code == 303
    token = _csrf(real_console_client, "/analysis")
    sweep_response = real_console_client.post(
        "/analysis/size-sweep", data={"csrf_token": token}, base_url="https://localhost"
    )
    assert sweep_response.status_code == 200
    sweep_html = sweep_response.get_data(as_text=True)

    def assert_wrapped_tables(html, expected):
        regions = re.findall(
            r'<div(?=[^>]*class="chart-scroll-region")(?=[^>]*role="region")'
            r'(?=[^>]*tabindex="0")(?=[^>]*aria-label="[^"]+")[^>]*>(.*?)</div>',
            html, re.I | re.S,
        )
        tables = re.findall(
            r'<table(?=[^>]*class="[^"]*chart-data-table[^"]*")[^>]*>', html, re.I,
        )
        assert len(regions) == expected
        assert len(tables) == expected
        assert all(re.search(r'<table(?=[^>]*class="[^"]*chart-data-table)', region, re.I) for region in regions)

    assert_wrapped_tables(sweep_html, 5)
    assert len(re.findall(r'<section class="sweep-operation"', sweep_html)) == 5

    monkeypatch.setattr(console, "sha256_analysis", lambda data: _analysis_result("sha256"))
    token = _csrf(real_console_client, "/analysis")
    sha_response = real_console_client.post(
        "/analysis/sha256", data={"csrf_token": token}, base_url="https://localhost"
    )
    assert sha_response.status_code == 200
    assert_wrapped_tables(sha_response.get_data(as_text=True), 3)

    css = (_STATIC_ROOT / "console.css").read_text(encoding="utf-8")
    assert re.search(
        r"\.chart-scroll-region\s*\{[^}]*max-width:\s*100%;[^}]*overflow-x:\s*auto\s*;?\s*\}",
        css, re.S,
    )
    compact_css = re.sub(r"\s+", "", css)
    assert ".chart-data-table{display:block;overflow-x:auto}" not in compact_css

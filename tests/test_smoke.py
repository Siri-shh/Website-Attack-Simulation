"""Production-template route integration with temporary, persistent lab data.

These tests use normal forms and real crypto/DB services. Actual HTTPS sockets,
capture processes and server restart are verified by the controller separately.
"""

from contextlib import closing

import pytest

from docker_smoke import ALICE_ID, assert_cascade, csrf, detail_evidence
from security_lab import cli
from security_lab import auth, config as security_config, records
from security_lab.config import format_ist
from security_lab.console import create_console_app
from security_lab.crypto import open_record
from security_lab.db import connect
from security_lab.identity import load_or_create_keys
from security_lab.storage import create_storage_app


PEER = "192.0.2.10"
BASE = "https://localhost"


@pytest.fixture
def lab(config, monkeypatch):
    """Initialize production seeds without conftest's template substitutions."""
    monkeypatch.setattr(cli, "load_config", lambda: config)
    assert cli.main(["init"]) == 0
    keys = load_or_create_keys(config)
    storage = create_storage_app(config, keys)
    console = create_console_app(config, keys)
    storage.config["TESTING"] = console.config["TESTING"] = True
    return config, keys, storage.test_client(), console.test_client()


def request(client, method, route, data=None):
    return client.open(route, method=method, data=data, base_url=BASE,
                       environ_overrides={"REMOTE_ADDR": PEER}, follow_redirects=False)


def page(client, route):
    response = request(client, "GET", route)
    assert response.status_code == 200
    return response.get_data(as_text=True)


def login(client, username, password, expected=303):
    response = request(client, "POST", "/login", {
        "username": username, "password": password,
        "csrf_token": csrf(page(client, "/login")),
    })
    assert response.status_code == expected


def row(config, record_id):
    with closing(connect(config)) as conn:
        return dict(conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone())


def snapshot(admin):
    response = request(admin, "GET", "/api/snapshot")
    assert response.status_code == 200
    return response.get_json()


def assert_saved_display(html, saved):
    evidence = detail_evidence(html)
    assert evidence["version"] == saved["version"]
    for key in ("ciphertext_b64", "nonce_b64", "sha256_hex", "signature_b64"):
        assert evidence[key] == saved[key]
    assert evidence["times"] == [format_ist(saved[key]) for key in
                                 ("created_at_us", "updated_at_us", "generated_at_us")]
    assert evidence["sizes"] == [saved[key] for key in
                                 ("plaintext_bytes", "ciphertext_bytes", "envelope_bytes")]
    assert evidence["durations_ms"] == [f"{saved[key] / 1_000_000:.6f}" for key in
                                        ("encryption_ns", "hashing_ns", "signing_ns")]
    return evidence


def block(admin):
    response = request(admin, "POST", "/blocks", {
        "ip": PEER, "reason": "reviewed smoke evidence", "csrf_token": csrf(page(admin, "/")),
    })
    assert response.status_code == 303


def unblock(admin):
    response = request(admin, "POST", f"/blocks/{PEER}/remove", {
        "csrf_token": csrf(page(admin, "/")),
    })
    assert response.status_code == 303


def test_normal_forms_save_complete_evidence_and_timings_through_edit_and_reload(lab):
    config, keys, bob, admin = lab
    login(bob, "bob", "BobDemo!2026")
    landing = page(bob, "/")
    assert "Login successful" in landing
    assert "Alice's record" not in landing and ALICE_ID not in landing

    response = request(bob, "POST", "/records/new", {
        "title": "Created through ordinary forms", "body": "Persistent smoke body",
        "csrf_token": csrf(page(bob, "/records/new")),
    })
    assert response.status_code == 303
    route = response.headers["Location"]
    record_id = route.rsplit("/", 1)[1]
    created = row(config, record_id)
    assert created["owner"] == "bob" and created["version"] == 1
    displayed = assert_saved_display(page(bob, route), created)
    assert assert_saved_display(page(bob, route), created) == displayed
    assert row(config, record_id) == created

    response = request(bob, "POST", route + "/edit", {
        "title": "Edited through ordinary forms", "body": "Edited persistent smoke body",
        "csrf_token": csrf(page(bob, route + "/edit")),
    })
    assert response.status_code == 303 and response.headers["Location"] == route
    edited = row(config, record_id)
    assert edited["owner"] == "bob" and edited["version"] == 2
    assert edited["created_at_us"] == created["created_at_us"]
    assert edited["updated_at_us"] > created["updated_at_us"]
    assert edited["generated_at_us"] == edited["updated_at_us"]
    assert all(edited[key] != created[key] for key in
               ("nonce_b64", "ciphertext_b64", "sha256_hex", "signature_b64"))
    assert open_record(keys, edited) == {
        "title": "Edited through ordinary forms", "body": "Edited persistent smoke body",
    }
    displayed = assert_saved_display(page(bob, route), edited)
    assert assert_saved_display(page(bob, route), edited) == displayed
    assert row(config, record_id) == edited

    # Reload identity/app factories without initialization or resetting data.
    fresh_keys = load_or_create_keys(config)
    fresh_bob = create_storage_app(config, fresh_keys).test_client()
    login(fresh_bob, "bob", "BobDemo!2026")
    assert assert_saved_display(page(fresh_bob, route), edited) == displayed
    assert row(config, record_id) == edited

    alice = row(config, ALICE_ID)
    denied = request(fresh_bob, "GET", f"/records/{ALICE_ID}")
    assert denied.status_code == 403
    denied_html = denied.get_data(as_text=True)
    assert "Alice's record" not in denied_html
    assert "Alice's ordinary demonstration record." not in denied_html
    assert "Cryptographic evidence" not in denied_html
    assert "Measured operation durations" not in denied_html
    for key in ("ciphertext_b64", "nonce_b64", "sha256_hex", "signature_b64"):
        assert alice[key] not in denied_html


def test_actual_login_denial_rules_and_existing_cookie_block_survive_app_reload(lab, monkeypatch):
    config, keys, bob, admin = lab
    clock = [security_config.utc_us()]
    monkeypatch.setattr(auth, "utc_us", lambda: clock[0])
    monkeypatch.setattr(records, "utc_us", lambda: clock[0])
    # Console admits only an administrator; a user's credentials cannot enter.
    login(admin, "bob", "BobDemo!2026", expected=401)
    assert request(admin, "GET", "/api/snapshot").status_code == 302
    login(admin, "admin", "AdminDemo!2026")
    baseline = snapshot(admin)
    baseline_ids = {alert["id"] for alert in baseline["alerts"]}

    for index in range(5):
        login(bob, "bob", f"wrong smoke password {index}", expected=401)
    login(bob, "bob", "BobDemo!2026", expected=429)
    clock[0] += 90_000_000
    login(bob, "bob", "BobDemo!2026")
    denied = request(bob, "GET", f"/records/{ALICE_ID}")
    assert denied.status_code == 403
    current = snapshot(admin)
    events = {event["event_id"]: event for event in current["events"]}
    alerts = [alert for alert in current["alerts"] if alert["id"] not in baseline_ids]
    by_rule = assert_cascade(alerts, events, source=PEER, denied_record=ALICE_ID)
    preserved_ids = {alert["id"] for alert in alerts}
    login_event = events[by_rule["R3"]["trigger_event_id"]]
    assert all(events[event_id]["dst_port"] == config.storage_port
               and events[event_id]["dst_ip"] == config.server_ip
               for alert in alerts for event_id in alert["evidence"]["event_ids"])

    # A storage cookie cannot authenticate to the independent console secret.
    other_console = create_console_app(config, keys).test_client()
    cookie = bob.get_cookie("storage_session", domain="localhost")
    assert cookie is not None
    other_console.set_cookie("console_session", cookie.value, domain="localhost")
    assert request(other_console, "GET", "/api/snapshot").status_code == 302

    seed_before = row(config, "00000000000000000000000000000001")
    block(admin)
    assert request(bob, "GET", "/").status_code == 403
    assert "Security" in page(admin, "/")
    current = snapshot(admin)
    assert [entry["ip"] for entry in current["blocks"]] == [PEER]
    blocked = next(event for event in current["events"] if event["kind"] == "blocked_request")
    assert blocked["signature_valid"] is True
    assert blocked["username"] == "bob" and blocked["session_ref"] == login_event["session_ref"]
    assert blocked["src_ip"] == PEER

    # Retain the block, reopen persisted keys, and carry actual signed cookies
    # into freshly created apps. No direct session mutation or state injection.
    fresh_keys = load_or_create_keys(config)
    fresh_bob = create_storage_app(config, fresh_keys).test_client()
    fresh_admin = create_console_app(config, fresh_keys).test_client()
    storage_cookie = bob.get_cookie("storage_session", domain="localhost")
    console_cookie = admin.get_cookie("console_session", domain="localhost")
    assert storage_cookie is not None and console_cookie is not None
    fresh_bob.set_cookie("storage_session", storage_cookie.value, domain="localhost")
    fresh_admin.set_cookie("console_session", console_cookie.value, domain="localhost")
    assert request(fresh_bob, "GET", "/").status_code == 403
    reopened = snapshot(fresh_admin)
    assert [entry["ip"] for entry in reopened["blocks"]] == [PEER]
    assert preserved_ids <= {alert["id"] for alert in reopened["alerts"]}
    assert set(events) <= {event["event_id"] for event in reopened["events"]}
    assert row(config, seed_before["id"]) == seed_before
    unblock(fresh_admin)
    assert page(fresh_bob, "/")
    assert snapshot(fresh_admin)["blocks"] == []
    assert row(config, seed_before["id"]) == seed_before

"""Behavioral contracts for storage and console authentication."""

from contextlib import closing, contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
from threading import Event, local

from flask import Flask, session
import pytest
from werkzeug.security import generate_password_hash

from security_lab.auth import configure_auth, require_login
from security_lab.audit import verify_app_event
from security_lab.db import connect, transaction


SECOND = 1_000_000
START = 1_700_000_000_000_000


def _make_app(config, keys, role):
    app = Flask(
        f"test-{role}",
        template_folder=str(Path(__file__).parents[1] / "security_lab" / "templates"),
    )
    configure_auth(app, config, keys, required_role=role)

    @app.get("/protected")
    @require_login(role)
    def protected():
        return {"username": session["username"], "session_ref": session["session_ref"]}

    return app


def _token(client):
    response = client.get("/login", base_url="https://localhost")
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.data.decode("utf-8")
    return match.group(1).decode("ascii")


def _event_rows(config):
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY seq")]


def _alerts(config, rule="R2"):
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM alerts WHERE domain='live' AND rule=? ORDER BY time_us,id", (rule,)
        )]


def _login(client, username, password, *, ip="192.0.2.10"):
    return client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": username, "password": password},
        environ_overrides={"REMOTE_ADDR": ip},
    )


def _trigger_r2(storage, *, username="bob", ip="192.0.2.10"):
    client = storage.test_client()
    for _ in range(5):
        assert _login(client, username, "wrong", ip=ip).status_code == 401
    return client


def _assert_event(config, keys, *, kind, username, session_ref, src_ip="192.0.2.10"):
    rows = _event_rows(config)
    matches = [row for row in rows if row["kind"] == kind]
    assert matches, rows
    row = matches[-1]
    assert row["username"] == username
    assert row["session_ref"] == session_ref
    assert row["src_ip"] == src_ip
    assert verify_app_event(keys, row)
    return row


@pytest.fixture
def auth_apps(config, keys):
    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES(?,?,?,?)",
            [
                ("bob", "user", generate_password_hash("BobPass!2026", method="scrypt"), 1),
                ("alice", "user", generate_password_hash("AlicePass!2026", method="scrypt"), 2),
                ("admin", "admin", generate_password_hash("AdminPass!2026", method="scrypt"), 3),
            ],
        )
    storage = _make_app(config, keys, "user")
    console = _make_app(config, keys, "admin")
    return config, keys, storage, console


def test_storage_login_accepts_bob_and_issues_fresh_secure_session(auth_apps):
    config, keys, storage, _ = auth_apps
    client = storage.test_client()
    response = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": "  Bob  ", "password": "BobPass!2026"},
        follow_redirects=False, environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/")
    cookie = client.get_cookie("storage_session", domain="localhost")
    assert cookie is not None
    assert cookie.secure and cookie.http_only and cookie.same_site == "Lax"
    result = client.get("/protected", base_url="https://localhost")
    assert result.status_code == 200
    assert result.json["username"] == "bob"
    first_ref = result.json["session_ref"]
    assert first_ref
    again = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": "bob", "password": "BobPass!2026"},
        follow_redirects=False, environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert again.status_code == 303
    renewed = client.get("/protected", base_url="https://localhost")
    assert renewed.status_code == 200
    assert renewed.json["session_ref"] != first_ref
    _assert_event(config, keys, kind="login_success", username="bob", session_ref=renewed.json["session_ref"])


def test_each_app_rejects_the_other_apps_role(auth_apps):
    config, keys, storage, console = auth_apps
    checks = [
        (storage, "admin", "AdminPass!2026", "login_failure", "admin"),
        (console, "bob", "BobPass!2026", "admin_login_failure", "bob"),
    ]
    for app, username, password, expected_kind, expected_user in checks:
        client = app.test_client()
        response = client.post(
            "/login", base_url="https://localhost",
            data={"csrf_token": _token(client), "username": username, "password": password},
            environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
        )
        assert response.status_code == 401
        protected = client.get("/protected", base_url="https://localhost")
        assert protected.status_code in (302, 303)
        assert "username" not in protected.json if protected.is_json else True
        row = _assert_event(config, keys, kind=expected_kind, username=expected_user, session_ref=None)
        assert row["outcome"] == "console_login_denied" if app is console else row["outcome"] == "login_denied"


def test_invalid_or_missing_csrf_returns_400_without_auth_failure_event(auth_apps):
    config, keys, storage, _ = auth_apps
    client = storage.test_client()
    _token(client)
    before = len(_event_rows(config))
    for token in (None, "forged-token", "forged-é"):
        data = {"username": "bob", "password": "wrong"}
        if token is not None:
            data["csrf_token"] = token
        response = client.post("/login", base_url="https://localhost", data=data)
        assert response.status_code == 400
        assert client.get("/protected", base_url="https://localhost").status_code in (302, 303)
    assert len(_event_rows(config)) == before


def test_wrong_password_logs_failure_and_clears_previous_identity(auth_apps):
    config, keys, storage, _ = auth_apps
    client = storage.test_client()
    client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": "bob", "password": "BobPass!2026"},
    )
    previous = client.get("/protected", base_url="https://localhost").json["session_ref"]
    response = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": "bob", "password": "wrong"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 401
    denied = client.get("/protected", base_url="https://localhost")
    assert denied.status_code in (302, 303)
    row = _assert_event(config, keys, kind="login_failure", username="bob", session_ref=None)
    assert row["outcome"] == "login_denied"
    assert all(event["session_ref"] != previous for event in _event_rows(config) if event["kind"] == "login_failure")


def test_cookie_names_and_signing_secrets_are_independent(auth_apps):
    _, _, storage, console = auth_apps
    storage_client, console_client = storage.test_client(), console.test_client()
    assert storage.secret_key != console.secret_key
    assert storage.config["SESSION_COOKIE_NAME"] == "storage_session"
    assert console.config["SESSION_COOKIE_NAME"] == "console_session"
    assert storage.config["SESSION_COOKIE_SECURE"] is True
    assert console.config["SESSION_COOKIE_SECURE"] is True
    assert storage.config["SESSION_COOKIE_HTTPONLY"] is True
    assert console.config["SESSION_COOKIE_HTTPONLY"] is True
    assert storage.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert console.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    storage_client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(storage_client), "username": "bob", "password": "BobPass!2026"},
    )
    storage_cookie = storage_client.get_cookie("storage_session", domain="localhost")
    assert storage_cookie is not None
    console_client.set_cookie("console_session", storage_cookie.value, domain="localhost")
    result = console_client.get("/protected", base_url="https://localhost")
    assert result.status_code in (302, 303)


def test_block_denies_an_already_authenticated_storage_peer_and_logs_it(auth_apps):
    config, keys, storage, _ = auth_apps
    client = storage.test_client()
    login = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": "bob", "password": "BobPass!2026"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.77"},
    )
    assert login.status_code == 303
    prior = client.get("/protected", base_url="https://localhost",
                       environ_overrides={"REMOTE_ADDR": "192.0.2.77"})
    assert prior.status_code == 200
    authenticated_ref = prior.json["session_ref"]
    with transaction(config) as conn:
        conn.execute("INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?)",
                     ("192.0.2.77", 4, "admin", "test block"))
    response = client.get("/protected", base_url="https://localhost",
                          environ_overrides={"REMOTE_ADDR": "192.0.2.77"})
    assert response.status_code == 403
    _assert_event(config, keys, kind="blocked_request", username="bob",
                  session_ref=authenticated_ref, src_ip="192.0.2.77")


def test_forged_forwarded_ip_cannot_bypass_block_and_admin_app_is_unaffected(auth_apps):
    config, keys, storage, console = auth_apps
    with transaction(config) as conn:
        conn.execute("INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?)",
                     ("192.0.2.10", 4, "admin", "test block"))
    storage_client = storage.test_client()
    blocked = storage_client.get(
        "/protected", base_url="https://localhost",
        environ_overrides={"REMOTE_ADDR": "192.0.2.10", "HTTP_X_FORWARDED_FOR": "198.51.100.9"},
    )
    assert blocked.status_code == 403
    row = _assert_event(config, keys, kind="blocked_request", username=None, session_ref=None, src_ip="192.0.2.10")
    assert row["src_ip"] != "198.51.100.9"

    console_client = console.test_client()
    login = console_client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(console_client), "username": "admin", "password": "AdminPass!2026"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert login.status_code == 303
    protected = console_client.get("/protected", base_url="https://localhost",
                                   environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
    assert protected.status_code == 200
    assert protected.json["username"] == "admin"
    admin_ref = protected.json["session_ref"]
    assert admin_ref
    event = _assert_event(config, keys, kind="admin_login_success", username="admin",
                          session_ref=admin_ref, src_ip="192.0.2.10")
    assert event["outcome"] == "console_login_ok"


@pytest.mark.parametrize(("app_key", "username", "password"), [
    ("storage", "bob", "BobPass!2026"),
    ("console", "admin", "AdminPass!2026"),
])
def test_logout_requires_csrf_then_logs_departing_identity_and_clears_session(auth_apps, app_key, username, password):
    config, keys, storage, console = auth_apps
    app = storage if app_key == "storage" else console
    client = app.test_client()
    login = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": _token(client), "username": username, "password": password},
    )
    assert login.status_code == 303
    authenticated = client.get("/protected", base_url="https://localhost")
    assert authenticated.status_code == 200
    session_ref = authenticated.json["session_ref"]
    csrf = _token(client)
    with client.session_transaction(base_url="https://localhost") as current:
        assert current["username"] == username
        assert current["session_ref"] == session_ref
        assert current["csrf"] == csrf

    before = len([row for row in _event_rows(config) if row["kind"] == "logout"])
    for data in ({"csrf_token": ""}, {"csrf_token": "incorrect-token"},
                 {"csrf_token": "forged-é"}):
        rejected = client.post("/logout", base_url="https://localhost", data=data)
        assert rejected.status_code == 400
        remains = client.get("/protected", base_url="https://localhost")
        assert remains.status_code == 200
        assert remains.json["username"] == username
        assert remains.json["session_ref"] == session_ref
    assert len([row for row in _event_rows(config) if row["kind"] == "logout"]) == before

    response = client.post("/logout", base_url="https://localhost", data={"csrf_token": csrf})
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/login")
    with client.session_transaction(base_url="https://localhost") as cleared:
        assert not {"username", "role", "session_ref", "csrf"} & set(cleared)
    assert client.get("/protected", base_url="https://localhost").status_code in (302, 303)
    logout_rows = [row for row in _event_rows(config) if row["kind"] == "logout"]
    assert len(logout_rows) == before + 1
    row = _assert_event(config, keys, kind="logout", username=username, session_ref=session_ref,
                        src_ip="127.0.0.1")
    assert row["outcome"] == "logout"


def test_blocked_storage_request_discards_wrong_role_session_context(auth_apps):
    config, keys, storage, _ = auth_apps
    client = storage.test_client()
    with client.session_transaction(base_url="https://localhost") as invalid_session:
        invalid_session["role"] = "admin"
        invalid_session["username"] = "bob"
        invalid_session["session_ref"] = "wrong-role-ref"
    with transaction(config) as conn:
        conn.execute("INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?)",
                     ("192.0.2.10", 4, "admin", "test block"))
    response = client.get(
        "/protected", base_url="https://localhost",
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 403
    _assert_event(config, keys, kind="blocked_request", username=None, session_ref=None,
                  src_ip="192.0.2.10")


def test_r2_restricts_only_matching_ip_username_for_exact_90_seconds(auth_apps, monkeypatch):
    config, keys, storage, _ = auth_apps
    now = [START]
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: now[0])
    client = _trigger_r2(storage)
    r2 = _alerts(config)
    assert len(r2) == 1
    assert r2[0]["time_us"] == START
    assert len([row for row in _event_rows(config) if row["kind"] == "login_failure"]) == 5

    restricted = _login(client, "  Bob  ", "BobPass!2026")
    assert restricted.status_code == 429
    assert restricted.headers["Retry-After"] == "90"
    assert client.get("/protected", base_url="https://localhost").status_code in (302, 303)

    # Both dimensions of the pair are independent; neither is covered by Bob's R2.
    assert _login(storage.test_client(), "alice", "AlicePass!2026").status_code == 303
    assert _login(storage.test_client(), "bob", "BobPass!2026", ip="192.0.2.11").status_code == 303

    now[0] = START + 90 * SECOND - 1
    last_microsecond = _login(client, "bob", "BobPass!2026")
    assert last_microsecond.status_code == 429
    assert last_microsecond.headers["Retry-After"] == "1"
    restricted_rows = [row for row in _event_rows(config) if row["kind"] == "login_restricted_attempt"]
    assert len(restricted_rows) == 2
    assert all(row["outcome"] == "login_restricted_attempt" and row["username"] == "bob"
               and row["session_ref"] is None and verify_app_event(keys, row)
               for row in restricted_rows)
    assert len([row for row in _event_rows(config) if row["kind"] == "login_failure"]) == 5
    assert len(_alerts(config)) == 1

    now[0] = START + 90 * SECOND
    assert _login(client, "bob", "BobPass!2026").status_code == 303
    assert client.get("/protected", base_url="https://localhost").json["username"] == "bob"
    assert len(_alerts(config, "R3")) == 1


def test_concurrent_fifth_and_sixth_login_serializes(auth_apps, monkeypatch):
    config, keys, storage, _ = auth_apps
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: START)
    first = storage.test_client()
    for _ in range(4):
        assert _login(first, "bob", "wrong").status_code == 401

    import security_lab.auth as auth
    original_append = auth.append_app_event
    original_transaction = auth.transaction
    fifth_holds_transaction = Event()
    release_fifth = Event()
    sixth_entered_decision = Event()
    attempt = local()

    def controlled_append(conn, event_keys, payload):
        if payload["kind"] == "login_failure" and not fifth_holds_transaction.is_set():
            fifth_holds_transaction.set()
            assert release_fifth.wait(10)
        return original_append(conn, event_keys, payload)

    monkeypatch.setattr(auth, "append_app_event", controlled_append)
    sixth = storage.test_client()
    fifth_token, sixth_token = _token(first), _token(sixth)

    # Remove the earlier admission transaction so this test isolates the login
    # decision transaction. The tokens and initial failures used the real hook.
    admission_hooks = storage.before_request_funcs[None]
    admission_index = next(index for index, hook in enumerate(admission_hooks)
                           if hook.__name__ == "_storage_admission")
    admission_hooks[admission_index] = lambda: None

    @contextmanager
    def observed_transaction(current_config):
        if getattr(attempt, "name", None) == "sixth":
            sixth_entered_decision.set()
        with original_transaction(current_config) as conn:
            yield conn

    monkeypatch.setattr(auth, "transaction", observed_transaction)

    def submit(client, token, password):
        attempt.name = "sixth" if password == "BobPass!2026" else "fifth"
        try:
            return client.post(
                "/login", base_url="https://localhost",
                data={"csrf_token": token, "username": "bob", "password": password},
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            )
        finally:
            del attempt.name

    with ThreadPoolExecutor(max_workers=2) as pool:
        fifth = pool.submit(submit, first, fifth_token, "wrong")
        assert fifth_holds_transaction.wait(10)
        sixth_future = pool.submit(submit, sixth, sixth_token, "BobPass!2026")
        try:
            assert sixth_entered_decision.wait(5)
        finally:
            release_fifth.set()
        assert fifth.result(timeout=10).status_code == 401
        sixth_response = sixth_future.result(timeout=10)

    assert sixth_response.status_code == 429
    assert sixth_response.headers["Retry-After"] == "90"
    assert sixth.get("/protected", base_url="https://localhost").status_code in (302, 303)
    assert len(_alerts(config)) == 1
    assert not [row for row in _event_rows(config) if row["kind"] == "login_success"]
    _assert_event(config, keys, kind="login_restricted_attempt", username="bob", session_ref=None)


def test_manual_block_precedes_r2_restriction(auth_apps, monkeypatch):
    config, keys, storage, _ = auth_apps
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: START)
    client = _trigger_r2(storage)
    token = _token(client)
    with transaction(config) as conn:
        conn.execute("INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?)",
                     ("192.0.2.10", START, "admin", "test block"))
    before = len(_event_rows(config))
    blocked = client.post(
        "/login", base_url="https://localhost",
        data={"csrf_token": token, "username": "bob", "password": "BobPass!2026"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert blocked.status_code == 403
    rows = _event_rows(config)
    assert len(rows) == before + 1
    assert rows[-1]["kind"] == "blocked_request"
    assert verify_app_event(keys, rows[-1])
    assert not [row for row in rows if row["kind"] == "login_restricted_attempt"]


def test_r2_does_not_interrupt_existing_storage_session(auth_apps, monkeypatch):
    config, _, storage, _ = auth_apps
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: START)
    existing = storage.test_client()
    assert _login(existing, "bob", "BobPass!2026").status_code == 303
    original = existing.get("/protected", base_url="https://localhost").json["session_ref"]
    _trigger_r2(storage)
    assert len(_alerts(config)) == 1
    protected = existing.get("/protected", base_url="https://localhost",
                             environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
    assert protected.status_code == 200
    assert protected.json["session_ref"] == original


def test_admin_login_and_offline_r2_do_not_restrict_live_storage(auth_apps, monkeypatch):
    config, _, storage, console = auth_apps
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: START)
    _trigger_r2(storage, username="admin")
    assert len(_alerts(config)) == 1
    assert _login(console.test_client(), "admin", "AdminPass!2026").status_code == 303

    with transaction(config) as conn:
        conn.execute(
            "INSERT INTO alerts(id,domain,rule,src_ip,username,session_ref,time_us,"
            "trigger_event_id,severity,summary,evidence_json,dedup_key) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("offline-r2", "offline:example", "R2", "192.0.2.11", "bob", None,
             START, "offline-trigger", "warning", "offline replay", "{}", "offline-trigger"),
        )
    assert _login(storage.test_client(), "bob", "BobPass!2026", ip="192.0.2.11").status_code == 303


@pytest.mark.parametrize(("delay_us", "expect_r3"), [
    (90 * SECOND, True),
    (120 * SECOND, True),
    (120 * SECOND + 1, False),
])
def test_r3_window_remains_120_seconds_after_r2(auth_apps, monkeypatch, delay_us, expect_r3):
    config, _, storage, _ = auth_apps
    now = [START]
    monkeypatch.setattr("security_lab.auth.utc_us", lambda: now[0])
    client = _trigger_r2(storage)
    now[0] += delay_us
    assert _login(client, "bob", "BobPass!2026").status_code == 303
    assert len(_alerts(config, "R3")) == int(expect_r3)

from __future__ import annotations

import socket

import pytest

from attacker_tools import client


class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)


def test_extract_csrf_token_from_login_form():
    html = '<form><input type="hidden" name="csrf_token" value="fresh-token"></form>'
    assert client.extract_csrf(html) == "fresh-token"


def test_extract_csrf_raises_when_form_has_no_token():
    with pytest.raises(ValueError):
        client.extract_csrf('<form><input name="other" value="x"></form>')


def test_login_attempts_fetches_fresh_csrf_and_stops_on_success(monkeypatch, tmp_path, capsys):
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("wrong-one\ncorrect-secret\nunused-secret\n", encoding="utf-8")
    session = FakeSession([
        FakeResponse(200, '<input name="csrf_token" value="csrf-1">'),
        FakeResponse(401),
        FakeResponse(200, '<input name="csrf_token" value="csrf-2">'),
        FakeResponse(303),
    ])
    monkeypatch.setattr(client.requests, "Session", lambda: session)

    result = client.main([
        "login-attempts", "--url", "https://lab.example:8443", "--username", "bob",
        "--password-file", str(password_file), "--limit", "3", "--ca", "/tmp/lab-ca.pem",
    ])

    assert result == 0
    assert [(method, url) for method, url, _ in session.calls] == [
        ("GET", "https://lab.example:8443/login"),
        ("POST", "https://lab.example:8443/login"),
        ("GET", "https://lab.example:8443/login"),
        ("POST", "https://lab.example:8443/login"),
    ]
    posts = [call for call in session.calls if call[0] == "POST"]
    assert posts[0][2]["data"] == {"username": "bob", "password": "wrong-one", "csrf_token": "csrf-1"}
    assert posts[1][2]["data"] == {"username": "bob", "password": "correct-secret", "csrf_token": "csrf-2"}
    for _, _, kwargs in posts:
        assert kwargs["allow_redirects"] is False
        assert kwargs["verify"] == "/tmp/lab-ca.pem"
        assert kwargs["timeout"] > 0
    output = capsys.readouterr().out
    assert "wrong-one" not in output and "correct-secret" not in output and "unused-secret" not in output
    assert "401" in output and "303" in output


def test_login_attempts_limit_validation_and_password_order(monkeypatch, tmp_path, capsys):
    pw = tmp_path / "candidates.txt"
    pw.write_text("first\nsecond\nthird\n", encoding="utf-8")
    session = FakeSession([
        FakeResponse(200, '<input name="csrf_token" value="a">'), FakeResponse(401),
        FakeResponse(200, '<input name="csrf_token" value="b">'), FakeResponse(401),
    ])
    monkeypatch.setattr(client.requests, "Session", lambda: session)
    rc = client.main(["login-attempts", "--url", "https://x", "--username", "u",
                      "--password-file", str(pw), "--limit", "2"])
    assert rc == 0
    posts = [c[2]["data"]["password"] for c in session.calls if c[0] == "POST"]
    assert posts == ["first", "second"]
    assert "first" not in capsys.readouterr().out

    for invalid in ("0", "1001"):
        assert client.main(["login-attempts", "--url", "https://x", "--username", "u",
                            "--password-file", str(pw), "--limit", invalid]) != 0


def test_login_attempts_stops_when_blocked_and_reports_other_errors(monkeypatch, tmp_path):
    pw = tmp_path / "candidates.txt"
    pw.write_text("one\ntwo\n", encoding="utf-8")
    session = FakeSession([FakeResponse(200, '<input name="csrf_token" value="a">'), FakeResponse(403)])
    monkeypatch.setattr(client.requests, "Session", lambda: session)
    assert client.main(["login-attempts", "--url", "https://x", "--username", "u",
                        "--password-file", str(pw), "--limit", "2"]) == 0
    assert len([c for c in session.calls if c[0] == "POST"]) == 1

    bad = FakeSession([FakeResponse(200, '<input name="csrf_token" value="a">'), FakeResponse(500)])
    monkeypatch.setattr(client.requests, "Session", lambda: bad)
    assert client.main(["login-attempts", "--url", "https://x", "--username", "u",
                        "--password-file", str(pw), "--limit", "1"]) != 0


def test_login_attempts_rejects_nonfinite_delay_and_never_weakens_tls(monkeypatch, tmp_path):
    pw = tmp_path / "candidates.txt"
    pw.write_text("candidate\n", encoding="utf-8")
    assert client.main(["login-attempts", "--url", "https://x", "--username", "u",
                        "--password-file", str(pw), "--limit", "1", "--delay", "nan"]) != 0
    session = FakeSession([FakeResponse(200, '<input name="csrf_token" value="a">'), FakeResponse(401)])
    monkeypatch.setattr(client.requests, "Session", lambda: session)
    assert client.main(["login-attempts", "--url", "https://x", "--username", "u",
                        "--password-file", str(pw), "--limit", "1", "--ca", "/ca.pem"]) == 0
    assert all(c[2].get("verify") == "/ca.pem" for c in session.calls)


def test_request_record_logs_in_then_gets_explicit_record_url(monkeypatch, capsys):
    session = FakeSession([
        FakeResponse(200, '<input name="csrf_token" value="login-csrf">'),
        FakeResponse(303),
        FakeResponse(200, "record page"),
    ])
    monkeypatch.setattr(client.requests, "Session", lambda: session)
    rc = client.main(["request-record", "--url", "https://lab.example:8443", "--username", "bob",
                      "--password", "secret", "--record-id", "record-123", "--ca", "/ca.pem"])
    assert rc == 0
    assert [(m, u) for m, u, _ in session.calls] == [
        ("GET", "https://lab.example:8443/login"),
        ("POST", "https://lab.example:8443/login"),
        ("GET", "https://lab.example:8443/records/record-123"),
    ]
    post = session.calls[1][2]
    assert post["data"] == {"username": "bob", "password": "secret", "csrf_token": "login-csrf"}
    assert post["allow_redirects"] is False
    assert all(c[2]["verify"] == "/ca.pem" for c in session.calls)
    assert "secret" not in capsys.readouterr().out


def test_probe_connects_only_explicit_host_and_ports(monkeypatch, capsys):
    observed = []

    class FakeSocket:
        def settimeout(self, value):
            observed.append(("timeout", value))
        def connect_ex(self, address):
            observed.append(("connect", address))
            return 0
        def close(self):
            observed.append(("close",))

    monkeypatch.setattr(client.socket, "socket", lambda *args: FakeSocket())
    rc = client.main(["probe", "--host", "192.0.2.20", "--ports", "8443,8444,8001", "--timeout", "0.25"])
    assert rc == 0
    assert [entry[1] for entry in observed if entry[0] == "connect"] == [
        ("192.0.2.20", 8443), ("192.0.2.20", 8444), ("192.0.2.20", 8001),
    ]
    assert all(entry[1] == pytest.approx(0.25) for entry in observed if entry[0] == "timeout")
    assert "192.0.2.20" in capsys.readouterr().out

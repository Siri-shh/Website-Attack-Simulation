"""Shared authentication, CSRF protection and storage admission hooks."""

from contextlib import closing
from functools import wraps
import secrets
from sqlite3 import Connection
import uuid

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .audit import append_app_event
from .config import Config, normalize_ip, utc_us
from .db import connect, transaction
from .identity import KeyRing


def _source_ip() -> str:
    """Return the normalized socket peer address, never a forwarded header."""
    try:
        return normalize_ip(request.remote_addr) if request.remote_addr else "unknown"
    except ValueError:
        return "unknown"


def _record_event(conn: Connection, config: Config, keys: KeyRing, *, kind: str, outcome: str,
                  username: str | None, session_ref: str | None, dst_port: int,
                  time_us: int | None = None, src_ip: str | None = None) -> None:
    """Sign an auth event with the actual peer and configured listener address."""
    payload = {
        "domain": "live",
        "event_id": uuid.uuid4().hex,
        "time_us": utc_us() if time_us is None else time_us,
        "kind": kind,
        "src_ip": _source_ip() if src_ip is None else src_ip,
        "dst_ip": config.server_ip,
        "dst_port": dst_port,
        "username": username,
        "session_ref": session_ref,
        "record_id": None,
        "outcome": outcome,
    }
    append_app_event(conn, keys, payload)


def restriction_expiry_us(conn: Connection, *, src_ip: str, username: str,
                          now_us: int) -> int | None:
    """Return the newest live R2 expiry for this peer/account while it is active."""
    alert = conn.execute(
        "SELECT time_us FROM alerts WHERE domain='live' AND rule='R2' "
        "AND src_ip=? AND username=? ORDER BY time_us DESC,id DESC LIMIT 1",
        (src_ip, username),
    ).fetchone()
    if alert is None:
        return None
    expiry_us = alert["time_us"] + 90_000_000
    return expiry_us if now_us < expiry_us else None


def _blocked_identity() -> tuple[str | None, str | None]:
    """Retain account context only for a valid authenticated storage session."""
    username = session.get("username")
    session_ref = session.get("session_ref")
    if (session.get("role") == "user" and isinstance(username, str) and bool(username)
            and isinstance(session_ref, str) and bool(session_ref)):
        return username, session_ref
    return None, None


def csrf_token() -> str:
    """Return a stable per-session random token for state-changing forms."""
    token = session.get("csrf")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def check_csrf() -> None:
    """Reject missing or mismatched form tokens with HTTP 400."""
    expected = session.get("csrf")
    submitted = request.form.get("csrf_token")
    if (not isinstance(expected, str) or not isinstance(submitted, str)
            or not expected or not submitted or not expected.isascii() or not submitted.isascii()
            or not secrets.compare_digest(expected, submitted)):
        abort(400)


def require_login(role: str):
    """Protect a view with the specified authenticated role."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if (session.get("role") != role or not isinstance(session.get("username"), str)
                    or not isinstance(session.get("session_ref"), str)):
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped
    return decorate


def configure_auth(app: Flask, config: Config, keys: KeyRing, *, required_role: str) -> None:
    """Configure isolated auth state and install login, logout and admission hooks."""
    if required_role not in {"user", "admin"}:
        raise ValueError("required_role must be user or admin")

    is_console = required_role == "admin"
    login_service = "admin" if is_console else "storage"
    app.secret_key = keys.console_session_secret if is_console else keys.storage_session_secret
    app.config.update(
        SESSION_COOKIE_NAME="console_session" if is_console else "storage_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=65_536,
    )

    @app.context_processor
    def _auth_template_context():
        return {"csrf_token": csrf_token}

    if not is_console:
        @app.before_request
        def _storage_admission():
            peer = _source_ip()
            if peer == "unknown":
                return None
            with transaction(config) as conn:
                blocked = conn.execute("SELECT 1 FROM blocks WHERE ip=?", (peer,)).fetchone()
                if blocked is None:
                    return None
                username, session_ref = _blocked_identity()
                _record_event(conn, config, keys, kind="blocked_request", outcome="blocked_request",
                              username=username, session_ref=session_ref, dst_port=config.storage_port,
                              src_ip=peer)
            return "Forbidden", 403

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            csrf_token()
            return render_template("login.html", login_service=login_service,
                                   login_error=None, restriction_seconds=None)

        check_csrf()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        with closing(connect(config)) as conn:
            row = conn.execute(
                "SELECT role, password_hash FROM users WHERE username=?", (username,)
            ).fetchone()
        valid_password = row is not None and check_password_hash(row["password_hash"], password)
        credential_valid = bool(valid_password and row["role"] == required_role)
        new_session_ref = secrets.token_urlsafe(32) if credential_valid else None
        peer = _source_ip()
        decision = "success" if credential_valid else "failure"
        restriction_seconds = None

        with transaction(config) as conn:
            now_us = utc_us()
            if not is_console and peer != "unknown" and conn.execute(
                    "SELECT 1 FROM blocks WHERE ip=?", (peer,)).fetchone() is not None:
                decision = "blocked"
                blocked_username, blocked_ref = _blocked_identity()
                _record_event(conn, config, keys, kind="blocked_request", outcome="blocked_request",
                              username=blocked_username, session_ref=blocked_ref,
                              dst_port=config.storage_port, time_us=now_us, src_ip=peer)
            else:
                expiry_us = (restriction_expiry_us(conn, src_ip=peer, username=username,
                                                   now_us=now_us)
                             if not is_console else None)
                if expiry_us is not None:
                    decision = "restricted"
                    restriction_seconds = (expiry_us - now_us + 999_999) // 1_000_000
                    kind = outcome = "login_restricted_attempt"
                    event_ref = None
                elif credential_valid:
                    kind = "admin_login_success" if is_console else "login_success"
                    outcome = "console_login_ok" if is_console else "login_ok"
                    event_ref = new_session_ref
                else:
                    kind = "admin_login_failure" if is_console else "login_failure"
                    outcome = "console_login_denied" if is_console else "login_denied"
                    event_ref = None
                _record_event(conn, config, keys, kind=kind, outcome=outcome,
                              username=username, session_ref=event_ref,
                              dst_port=config.console_port if is_console else config.storage_port,
                              time_us=now_us, src_ip=peer)

        if decision == "blocked":
            return "Forbidden", 403
        if decision == "restricted":
            session.clear()
            csrf_token()
            html = render_template("login.html", login_service=login_service,
                                   login_error="Sign-in temporarily restricted.",
                                   restriction_seconds=restriction_seconds)
            return html, 429, {"Retry-After": str(restriction_seconds)}
        if decision == "failure":
            # A failed attempt must never retain the previous account/session context.
            session.clear()
            csrf_token()
            return render_template("login.html", login_service=login_service,
                                   login_error="Invalid username or password.",
                                   restriction_seconds=None), 401

        session.clear()
        session["username"] = username
        session["role"] = required_role
        session["session_ref"] = new_session_ref
        session["csrf"] = secrets.token_urlsafe(32)
        flash("Login successful")
        return redirect("/", code=303)

    @app.post("/logout")
    @require_login(required_role)
    def logout():
        check_csrf()
        username = session["username"]
        session_ref = session["session_ref"]
        with transaction(config) as conn:
            _record_event(conn, config, keys, kind="logout", outcome="logout",
                          username=username, session_ref=session_ref,
                          dst_port=config.console_port if is_console else config.storage_port)
        session.clear()
        return redirect(url_for("login"), code=303)

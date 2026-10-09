"""Shared authentication, CSRF protection and storage admission hooks."""

from contextlib import closing
from functools import wraps
import secrets
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


def _record_event(config: Config, keys: KeyRing, *, kind: str, outcome: str,
                  username: str | None, session_ref: str | None, dst_port: int) -> None:
    """Sign an auth event with the actual peer and configured listener address."""
    payload = {
        "domain": "live",
        "event_id": uuid.uuid4().hex,
        "time_us": utc_us(),
        "kind": kind,
        "src_ip": _source_ip(),
        "dst_ip": config.server_ip,
        "dst_port": dst_port,
        "username": username,
        "session_ref": session_ref,
        "record_id": None,
        "outcome": outcome,
    }
    with transaction(config) as conn:
        append_app_event(conn, keys, payload)


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
                username = session.get("username")
                session_ref = session.get("session_ref")
                authenticated = (
                    session.get("role") == "user"
                    and isinstance(username, str) and bool(username)
                    and isinstance(session_ref, str) and bool(session_ref)
                )
                if not authenticated:
                    username = None
                    session_ref = None
                append_app_event(conn, keys, {
                    "domain": "live",
                    "event_id": uuid.uuid4().hex,
                    "time_us": utc_us(),
                    "kind": "blocked_request",
                    "src_ip": peer,
                    "dst_ip": config.server_ip,
                    "dst_port": config.storage_port,
                    "username": username,
                    "session_ref": session_ref,
                    "record_id": None,
                    "outcome": "blocked_request",
                })
            return "Forbidden", 403

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            csrf_token()
            return render_template("login.html")

        check_csrf()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        with closing(connect(config)) as conn:
            row = conn.execute(
                "SELECT role, password_hash FROM users WHERE username=?", (username,)
            ).fetchone()
        valid_password = row is not None and check_password_hash(row["password_hash"], password)
        if row is None or not valid_password or row["role"] != required_role:
            # A failed attempt must never retain the previous account/session context.
            session.clear()
            kind = "admin_login_failure" if is_console else "login_failure"
            outcome = "console_login_denied" if is_console else "login_denied"
            _record_event(config, keys, kind=kind, outcome=outcome,
                          username=username, session_ref=None,
                          dst_port=config.console_port if is_console else config.storage_port)
            csrf_token()
            return render_template("login.html"), 401

        session.clear()
        session["username"] = username
        session["role"] = required_role
        session["session_ref"] = secrets.token_urlsafe(32)
        session["csrf"] = secrets.token_urlsafe(32)
        kind = "admin_login_success" if is_console else "login_success"
        outcome = "console_login_ok" if is_console else "login_ok"
        _record_event(config, keys, kind=kind, outcome=outcome,
                      username=username, session_ref=session["session_ref"],
                      dst_port=config.console_port if is_console else config.storage_port)
        flash("Login successful")
        return redirect("/", code=303)

    @app.post("/logout")
    @require_login(required_role)
    def logout():
        check_csrf()
        username = session["username"]
        session_ref = session["session_ref"]
        _record_event(config, keys, kind="logout", outcome="logout",
                      username=username, session_ref=session_ref,
                      dst_port=config.console_port if required_role == "admin" else config.storage_port)
        session.clear()
        return redirect(url_for("login"), code=303)

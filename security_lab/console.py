"""Separate administrator console, bounded evidence snapshots and manual blocks."""

from contextlib import closing
import json
import uuid

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

from .audit import append_app_event, verify_app_event
from .auth import check_csrf, configure_auth, csrf_token, require_login
from .config import Config, format_ist, format_utc, normalize_ip, utc_us
from .db import connect, transaction
from .identity import KeyRing
from .analysis import (
    aes_gcm_analysis, aes_primitive_analysis, benchmark_size_sweep, sha256_analysis,
)


_EVENT_FIELDS = (
    "seq", "domain", "event_id", "time_us", "kind", "src_ip", "dst_ip", "dst_port",
    "username", "session_ref", "record_id", "outcome", "capture_id", "frame_number",
)
_ALERT_FIELDS = (
    "id", "domain", "rule", "src_ip", "username", "session_ref", "time_us",
    "trigger_event_id", "severity", "summary",
)
_CAPTURE_FIELDS = (
    "state", "started_at_us", "last_packet_at_us", "capture_path", "error",
)


def _capture_status(conn) -> dict:
    row = conn.execute("SELECT value_json FROM status WHERE key='capture'").fetchone()
    if row is None:
        return {"state": "stopped", "started_at_us": None, "last_packet_at_us": None,
                "capture_path": None, "error": None}
    try:
        value = json.loads(row["value_json"])
    except (TypeError, ValueError):
        value = None
    if not isinstance(value, dict):
        return {"state": "degraded", "started_at_us": None, "last_packet_at_us": None,
                "capture_path": None, "error": "Invalid capture status"}
    result = {field: value.get(field) for field in _CAPTURE_FIELDS}
    if result["state"] not in {"starting", "running", "degraded", "stopped"}:
        result["state"] = "degraded"
        result["error"] = result["error"] or "Invalid capture status"
    return result


def snapshot(config: Config, keys: KeyRing, domain: str = "live") -> dict:
    """Return a bounded, allowlisted view of events, findings and block state."""
    if not isinstance(domain, str) or not domain:
        domain = "live"
    with closing(connect(config)) as conn:
        domains = sorted(row[0] for row in conn.execute(
            "SELECT DISTINCT domain FROM events UNION SELECT DISTINCT domain FROM alerts"
        ))
        capture = _capture_status(conn)
        capture["last_packet_at_ist"] = (
            format_ist(capture["last_packet_at_us"])
            if type(capture["last_packet_at_us"]) is int else None
        )
        packet_rows = conn.execute(
            "SELECT * FROM events WHERE domain=? AND kind=? "
            "ORDER BY time_us DESC,seq DESC LIMIT ?",
            (domain, "connection_attempt", 100),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT * FROM events WHERE domain=? AND kind!=? "
            "ORDER BY time_us DESC,seq DESC LIMIT ?",
            (domain, "connection_attempt", 100),
        ).fetchall()
        event_rows = sorted(
            (*packet_rows, *audit_rows),
            key=lambda row: (row["time_us"], row["seq"]),
            reverse=True,
        )
        events = []
        for row in event_rows:
            item = {field: row[field] for field in _EVENT_FIELDS}
            if row["signature_b64"] is None and row["kind"] == "connection_attempt":
                item["signature_valid"] = None
            else:
                item["signature_valid"] = bool(verify_app_event(keys, row))
            item["time_utc"] = format_utc(row["time_us"])
            item["time_ist"] = format_ist(row["time_us"])
            events.append(item)

        alert_rows = conn.execute(
            "SELECT * FROM alerts WHERE domain=? ORDER BY time_us DESC,id DESC LIMIT 100",
            (domain,),
        ).fetchall()
        alerts = []
        snapshot_time_us = utc_us()
        for row in alert_rows:
            item = {field: row[field] for field in _ALERT_FIELDS}
            try:
                evidence = json.loads(row["evidence_json"])
            except (TypeError, ValueError):
                evidence = None
            item["evidence"] = evidence if isinstance(evidence, dict) else None
            item["time_utc"] = format_utc(row["time_us"])
            item["time_ist"] = format_ist(row["time_us"])
            expiry_us = row["time_us"] + 90_000_000 if domain == "live" and row["domain"] == "live" and row["rule"] == "R2" else None
            item["restriction_expires_at_us"] = expiry_us
            item["restriction_expires_at_ist"] = format_ist(expiry_us) if expiry_us is not None else None
            item["restriction_remaining_seconds"] = (
                max(0, (expiry_us - snapshot_time_us + 999_999) // 1_000_000)
                if expiry_us is not None else None
            )
            alerts.append(item)

        blocks = [dict(row) for row in conn.execute(
            "SELECT ip,created_by,reason,created_at_us FROM blocks ORDER BY ip"
        )]
        for block in blocks:
            block["created_at_ist"] = format_ist(block["created_at_us"])
    return {"domain": domain, "domains": domains, "capture": capture,
            "events": events, "alerts": alerts, "blocks": blocks}


def _source_ip() -> str:
    peer = request.remote_addr
    if not peer:
        return "unknown"
    try:
        return normalize_ip(peer)
    except ValueError:
        return "unknown"


def _target_ip(value: str) -> str:
    if not value:
        abort(400)
    try:
        return normalize_ip(value)
    except ValueError:
        abort(400)


def create_console_app(config: Config, keys: KeyRing) -> Flask:
    """Create the independent administrator application."""
    app = Flask(__name__, template_folder="templates")
    configure_auth(app, config, keys, required_role="admin")
    app.jinja_env.filters["utc"] = format_utc
    app.jinja_env.filters["ist"] = format_ist
    analysis_sample = "Cryptography analysis sample"

    @app.after_request
    def disable_analysis_caching(response):
        if request.path == "/analysis" or request.path.startswith("/analysis/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def render_analysis(result=None, result_type=None, input_text=analysis_sample, error=None, status=200):
        return render_template(
            "console/analysis.html",
            csrf_token=csrf_token(),
            input_text=input_text,
            result=result,
            result_type=result_type,
            analysis_error=error,
        ), status

    def analysis_input():
        text = request.form.get("input_text", "")
        if not text:
            text = analysis_sample
        data = text.encode("utf-8")
        if len(data) > 10240:
            abort(400)
        return data, text

    def run_analysis(result_type, function):
        check_csrf()
        data, text = analysis_input()
        try:
            result = function(data)
        except Exception:
            return render_analysis(input_text=text, error="Analysis could not be completed.", status=500)
        return render_analysis(result, result_type, text)

    @app.get("/")
    @require_login("admin")
    def dashboard():
        current = snapshot(config, keys)
        return render_template(
            "console/dashboard.html", snapshot=current, csrf_token=csrf_token(),
        )

    @app.get("/api/snapshot")
    @require_login("admin")
    def snapshot_api():
        domain = request.args.get("domain", "live")
        return jsonify(snapshot(config, keys, domain))

    @app.post("/blocks")
    @require_login("admin")
    def add_block():
        check_csrf()
        target = _target_ip(request.form.get("ip", ""))
        reason = request.form.get("reason", "")
        if len(reason) > 200:
            abort(400)
        with transaction(config) as conn:
            conn.execute(
                "INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET created_at_us=excluded.created_at_us, "
                "created_by=excluded.created_by,reason=excluded.reason",
                (target, utc_us(), session["username"], reason),
            )
            append_app_event(conn, keys, {
                "domain": "live", "event_id": uuid.uuid4().hex, "time_us": utc_us(),
                "kind": "admin_block", "src_ip": _source_ip(), "dst_ip": target,
                "dst_port": None, "username": session["username"],
                "session_ref": session["session_ref"], "record_id": None,
                "outcome": "admin_block",
            })
        return redirect(url_for("dashboard"), code=303)

    @app.post("/blocks/<path:ip>/remove")
    @require_login("admin")
    def remove_block(ip: str):
        check_csrf()
        target = _target_ip(ip)
        with transaction(config) as conn:
            conn.execute("DELETE FROM blocks WHERE ip=?", (target,))
            append_app_event(conn, keys, {
                "domain": "live", "event_id": uuid.uuid4().hex, "time_us": utc_us(),
                "kind": "admin_unblock", "src_ip": _source_ip(), "dst_ip": target,
                "dst_port": None, "username": session["username"],
                "session_ref": session["session_ref"], "record_id": None,
                "outcome": "admin_unblock",
            })
        return redirect(url_for("dashboard"), code=303)

    @app.get("/analysis")
    @require_login("admin")
    def analysis_page():
        return render_analysis()

    @app.post("/analysis/aes-gcm")
    @require_login("admin")
    def analysis_aes_gcm():
        return run_analysis("aes-gcm", aes_gcm_analysis)

    @app.post("/analysis/sha256")
    @require_login("admin")
    def analysis_sha256():
        return run_analysis("sha256", sha256_analysis)

    @app.post("/analysis/aes-primitive")
    @require_login("admin")
    def analysis_aes_primitive():
        return run_analysis("aes-primitive", aes_primitive_analysis)

    @app.post("/analysis/size-sweep")
    @require_login("admin")
    def analysis_size_sweep():
        check_csrf()
        try:
            result = benchmark_size_sweep()
        except Exception:
            return render_analysis(error="Analysis could not be completed.", status=500)
        return render_analysis(result, "size-sweep")

    return app

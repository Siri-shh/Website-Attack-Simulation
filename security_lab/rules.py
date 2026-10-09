"""Deterministic findings derived from persisted, transaction-local evidence."""

import hashlib
import json
from sqlite3 import Connection

from .config import normalize_ip
from .crypto import canonical_bytes
from .identity import KeyRing


_SECOND = 1_000_000
_SEVERITIES = {"R1": "info", "R2": "warning", "R3": "review", "R4": "blocked", "R5": "incident"}
_SUMMARIES = {
    "R1": "Five distinct server ports observed within 30 seconds",
    "R2": "Five failed storage logins within 60 seconds",
    "R3": "Storage login succeeded within 120 seconds after repeated failures",
    "R4": "Authenticated access to a foreign record was denied",
    "R5": "Repeated failures, successful login and denied foreign-record access in one session",
}


def _known_ip(value) -> bool:
    try:
        return isinstance(value, str) and normalize_ip(value) == value
    except ValueError:
        return False


def _nonempty(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _verified(keys, event) -> bool:
    # Local import keeps audit's new-insertion hook free of a module cycle.
    from .audit import verify_app_event

    return verify_app_event(keys, event)


def _packet(event) -> bool:
    # D24: the producer has already filtered incoming server SYNs without ACK.
    return (event["kind"] == "connection_attempt" and event["outcome"] == "observed"
            and event["signature_b64"] is None and _known_ip(event["src_ip"])
            and _known_ip(event["dst_ip"]) and type(event["dst_port"]) is int
            and 1 <= event["dst_port"] <= 65535 and _nonempty(event["capture_id"])
            and type(event["frame_number"]) is int and event["frame_number"] > 0)


def _window(conn, event, seconds, *, packet=False):
    context = "dst_ip=?" if packet else "username=?"
    value = event["dst_ip"] if packet else event["username"]
    kind, outcome = ("connection_attempt", "observed") if packet else ("login_failure", "login_denied")
    return [dict(row) for row in conn.execute(
        "SELECT * FROM events WHERE domain=? AND src_ip=? AND " + context +
        " AND kind=? AND outcome=? AND time_us BETWEEN ? AND ? AND seq<=? "
        "ORDER BY time_us,seq",
        (event["domain"], event["src_ip"], value, kind, outcome,
         event["time_us"] - seconds * _SECOND, event["time_us"], event["seq"]),
    )]


def _ordered_events(events):
    unique = {event["event_id"]: event for event in events}
    return sorted(unique.values(), key=lambda event: (event["time_us"], event["seq"]))


def _emit(conn, event, rule, events, *, linked=(), dedup=None):
    dedup = event["event_id"] if dedup is None else dedup
    identity = {"domain": event["domain"], "rule": rule, "dedup_key": dedup}
    alert_id = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    evidence = {"event_ids": [row["event_id"] for row in _ordered_events(events)],
                "alert_ids": list(dict.fromkeys(linked))}
    cursor = conn.execute(
        "INSERT INTO alerts(id,domain,rule,src_ip,username,session_ref,time_us,trigger_event_id,"
        "severity,summary,evidence_json,dedup_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(domain,rule,dedup_key) DO NOTHING",
        (alert_id, event["domain"], rule, event["src_ip"], event["username"],
         event["session_ref"], event["time_us"], event["event_id"], _SEVERITIES[rule],
         _SUMMARIES[rule], canonical_bytes(evidence).decode("utf-8"), dedup),
    )
    return alert_id, cursor.rowcount == 1


def _alert_events(conn, keys, alert, current):
    """Recheck signed evidence when a persistent finding is used by another rule."""
    try:
        identity = {"domain": alert["domain"], "rule": alert["rule"], "dedup_key": alert["dedup_key"]}
        if alert["id"] != hashlib.sha256(canonical_bytes(identity)).hexdigest():
            return None
        evidence = json.loads(alert["evidence_json"])
        ids = evidence["event_ids"]
        if (not isinstance(ids, list) or not ids or any(not isinstance(item, str) for item in ids)
                or len(ids) != len(set(ids)) or alert["trigger_event_id"] not in ids):
            return None
        found = []
        for event_id in ids:
            row = conn.execute("SELECT * FROM events WHERE domain=? AND event_id=? AND seq<=?",
                               (current["domain"], event_id, current["seq"])).fetchone()
            if row is None:
                return None
            event = dict(row)
            if (event["src_ip"] != current["src_ip"] or event["username"] != current["username"]
                    or not _verified(keys, event)):
                return None
            found.append(event)
        trigger = next(row for row in found if row["event_id"] == alert["trigger_event_id"])
        if (trigger["time_us"] != alert["time_us"] or trigger["session_ref"] != alert["session_ref"]
                or any(row["seq"] > trigger["seq"] or row["time_us"] > trigger["time_us"] for row in found)):
            return None
        if alert["rule"] == "R2":
            if (len(found) != 5 or any(row["kind"] != "login_failure" or row["outcome"] != "login_denied"
                                      or row["time_us"] < trigger["time_us"] - 60 * _SECOND for row in found)):
                return None
        elif alert["rule"] == "R3":
            if (trigger["kind"] != "login_success" or trigger["outcome"] != "login_ok"
                    or not _nonempty(trigger["session_ref"])):
                return None
        return _ordered_events(found)
    except (KeyError, TypeError, ValueError, StopIteration):
        return None


def _matching_alerts(conn, event, rule, seconds):
    session_clause = " AND a.session_ref=?" if rule == "R3" else ""
    parameters = [event["domain"], rule, event["src_ip"], event["username"],
                  event["time_us"] - seconds * _SECOND, event["time_us"], event["seq"]]
    if rule == "R3":
        parameters.append(event["session_ref"])
    return [dict(row) for row in conn.execute(
        "SELECT a.* FROM alerts AS a JOIN events AS e "
        "ON e.domain=a.domain AND e.event_id=a.trigger_event_id "
        "WHERE a.domain=? AND a.rule=? AND a.src_ip=? AND a.username=? "
        "AND a.time_us BETWEEN ? AND ? AND e.seq<=?" + session_clause +
        " ORDER BY a.time_us DESC,e.seq DESC", parameters,
    )]


def _r1(conn, event):
    rows = [row for row in _window(conn, event, 30, packet=True) if _packet(row)]
    before = {row["dst_port"] for row in rows if row["seq"] < event["seq"]}
    after = {row["dst_port"] for row in rows}
    if len(before) < 5 <= len(after):
        # SQL order is ascending; replacing a port keeps its newest representative.
        representatives = {row["dst_port"]: row for row in rows}
        return _emit(conn, event, "R1", representatives.values())
    return None


def _r2(conn, keys, event):
    if not isinstance(event["username"], str):
        return None
    rows = [row for row in _window(conn, event, 60) if _verified(keys, row)]
    before = [row for row in rows if row["seq"] < event["seq"]]
    if len(before) < 5 <= len(rows):
        return _emit(conn, event, "R2", rows[-5:])
    return None


def _r3(conn, keys, event):
    if not _nonempty(event["username"]) or not _nonempty(event["session_ref"]):
        return None
    for alert in _matching_alerts(conn, event, "R2", 120):
        evidence = _alert_events(conn, keys, alert, event)
        if evidence is not None:
            return _emit(conn, event, "R3", evidence + [event], linked=[alert["id"]])
    return None


def _r5(conn, keys, event, r4_id):
    for r3 in _matching_alerts(conn, event, "R3", 300):
        evidence = _alert_events(conn, keys, r3, event)
        if evidence is None:
            continue
        try:
            linked = json.loads(r3["evidence_json"])["alert_ids"]
            if not isinstance(linked, list) or len(linked) != 1 or not isinstance(linked[0], str):
                continue
            row = conn.execute("SELECT * FROM alerts WHERE id=? AND domain=? AND rule='R2' "
                               "AND src_ip=? AND username=?",
                               (linked[0], event["domain"], event["src_ip"], event["username"])).fetchone()
            if row is None:
                continue
            r2 = dict(row)
            login = next(row for row in evidence if row["event_id"] == r3["trigger_event_id"])
            r2_events = _alert_events(conn, keys, r2, login)
            if (r2_events is None or not 0 <= login["time_us"] - r2["time_us"] <= 120 * _SECOND
                    or {row["event_id"] for row in evidence} !=
                    {row["event_id"] for row in r2_events} | {login["event_id"]}):
                continue
            return _emit(conn, event, "R5", evidence + [event],
                         linked=[r2["id"], r3["id"], r4_id], dedup=event["session_ref"])
        except (KeyError, TypeError, ValueError, StopIteration):
            continue
    return None


def evaluate_event(conn: Connection, keys: KeyRing, domain: str, event_id: str) -> list[str]:
    """Evaluate stored evidence using only this connection; never commit or cache."""
    stored = conn.execute("SELECT * FROM events WHERE domain=? AND event_id=?", (domain, event_id)).fetchone()
    if stored is None:
        return []
    event = dict(stored)
    if not _known_ip(event["src_ip"]):
        return []
    results = []
    if _packet(event):
        result = _r1(conn, event)
        if result is not None and result[1]:
            results.append(result[0])
        return results
    if domain != "live" or not _verified(keys, event):
        return []
    if event["kind"] == "login_failure" and event["outcome"] == "login_denied":
        result = _r2(conn, keys, event)
    elif event["kind"] == "login_success" and event["outcome"] == "login_ok":
        result = _r3(conn, keys, event)
    elif (event["kind"] == "foreign_record_denied" and event["outcome"] == "foreign_record_denied"
          and all(_nonempty(event[field]) for field in ("username", "session_ref", "record_id"))):
        # D25: verified producer evidence attests existence, foreign ownership and auth.
        r4_id, created = _emit(conn, event, "R4", [event])
        if created:
            results.append(r4_id)
        result = _r5(conn, keys, event, r4_id)
    else:
        return []
    if result is not None and result[1]:
        results.append(result[0])
    return results

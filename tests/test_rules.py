"""Fixed-time behavioral checks for SQL-backed atomic detection."""

import base64
from contextlib import closing
import hashlib
import json

import pytest

from security_lab.audit import append_app_event
from security_lab.db import connect, transaction
from security_lab.identity import load_or_create_keys
from security_lab import rules


SECOND = 1_000_000
START = 1_700_000_000_000_000
SOURCE = "172.29.0.10"
DESTINATION = "172.29.0.20"
FIELDS = ("domain", "event_id", "time_us", "kind", "src_ip", "dst_ip",
          "dst_port", "username", "session_ref", "record_id", "outcome")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def app(number, seconds=0, **changes):
    value = dict(domain="live", event_id=f"{number:032x}", time_us=START + seconds * SECOND,
                 kind="login_failure", src_ip=SOURCE, dst_ip=DESTINATION, dst_port=8443,
                 username="bob", session_ref=None, record_id=None, outcome="login_denied")
    value.update(changes)
    return value


def packet(number, port, seconds=0, **changes):
    # These are accepted parser outputs: T13 owns server/SYN filtering (D24).
    value = dict(domain="live", event_id=f"capture:{number}", time_us=START + seconds * SECOND,
                 kind="connection_attempt", src_ip=SOURCE, dst_ip=DESTINATION, dst_port=port,
                 username=None, session_ref=None, record_id=None, outcome="observed",
                 capture_id="capture", frame_number=number, src_port=40000 + number,
                 tcp_seq_raw=number, retransmission=False)
    value.update(changes)
    return value


def insert(conn, keys, value, *, valid=True):
    """Insert independently signed rows so direct rule checks do not need the hook."""
    data = encoded(value)
    network = value["kind"] == "connection_attempt"
    signature = None if network else base64.b64encode(keys.signing_key.sign(data)).decode("ascii")
    if not valid:
        signature = base64.b64encode(bytes(64)).decode("ascii")
    conn.execute(
        "INSERT INTO events (domain,event_id,time_us,kind,src_ip,dst_ip,dst_port,username,"
        "session_ref,record_id,outcome,payload_json,signature_b64,capture_id,frame_number) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        tuple(value[field] for field in FIELDS) +
        (data.decode("utf-8"), signature, value.get("capture_id"), value.get("frame_number")),
    )
    return value["event_id"]


def evaluate(conn, keys, value):
    insert(conn, keys, value)
    return rules.evaluate_event(conn, keys, value["domain"], value["event_id"])


def alerts(conn, rule=None, domain="live"):
    query = "SELECT * FROM alerts WHERE domain=?"
    parameters = [domain]
    if rule:
        query += " AND rule=?"
        parameters.append(rule)
    return [dict(row) for row in conn.execute(query + " ORDER BY time_us,id", parameters)]


def assert_alert(row, rule, trigger, evidence, *, dedup=None, linked=()):
    dedup = trigger["event_id"] if dedup is None else dedup
    identity = {"domain": trigger["domain"], "rule": rule, "dedup_key": dedup}
    assert row["id"] == hashlib.sha256(encoded(identity)).hexdigest()
    assert row["domain"] == trigger["domain"] and row["rule"] == rule
    assert row["trigger_event_id"] == trigger["event_id"]
    assert row["dedup_key"] == dedup
    assert row["src_ip"] == trigger["src_ip"] and row["username"] == trigger["username"]
    assert row["time_us"] == trigger["time_us"]
    assert row["severity"] == {"R1": "info", "R2": "warning", "R3": "review",
                               "R4": "blocked", "R5": "incident"}[rule]
    assert isinstance(row["summary"], str) and row["summary"]
    data = json.loads(row["evidence_json"])
    assert set(data) == {"event_ids", "alert_ids"}
    assert data["event_ids"] == evidence
    assert set(data["alert_ids"]) == set(linked)
    assert len(data["alert_ids"]) == len(linked)


def failures(conn, keys, *, first=1, start=0, username="bob", source=SOURCE):
    values = [app(first + index, start + index, username=username, src_ip=source) for index in range(5)]
    for value in values:
        evaluate(conn, keys, value)
    return values


def success(number, seconds, **changes):
    return app(number, seconds, kind="login_success", outcome="login_ok", session_ref="session-a", **changes)


def denial(number, seconds, **changes):
    return app(number, seconds, kind="foreign_record_denied", outcome="foreign_record_denied",
               session_ref="session-a", record_id="alice-record", **changes)


@pytest.mark.parametrize("extra_us,expected", [(0, 1), (1, 0)])
def test_r1_thirty_second_boundary_and_duplicate_port(config, keys, extra_us, expected):
    with transaction(config) as conn:
        first = packet(1, 8000)
        evaluate(conn, keys, first)
        evaluate(conn, keys, packet(2, 8001, 1))
        repeated = packet(3, 8001, 2)
        evaluate(conn, keys, repeated)
        evaluate(conn, keys, packet(4, 8002, 3))
        evaluate(conn, keys, packet(5, 8003, 4))
        assert alerts(conn) == []
        trigger = packet(6, 8004, 30, time_us=START + 30 * SECOND + extra_us)
        emitted = evaluate(conn, keys, trigger)
        rows = alerts(conn, "R1")
        assert len(rows) == expected
        assert emitted == ([rows[0]["id"]] if expected else [])
        if expected:
            assert_alert(rows[0], "R1", trigger,
                         ["capture:1", "capture:3", "capture:4", "capture:5", "capture:6"])


def test_r1_domains_destinations_and_sources_are_separate(config, keys):
    with transaction(config) as conn:
        for number in range(1, 5):
            evaluate(conn, keys, packet(number, 8000 + number))
        for value in [packet(5, 8005, src_ip="172.29.0.11"),
                      packet(6, 8005, dst_ip="172.29.0.21"),
                      packet(7, 8005, domain="offline:file")]:
            assert evaluate(conn, keys, value) == []
        assert alerts(conn) == [] and alerts(conn, domain="offline:file") == []
        trigger = packet(8, 8005)
        evaluate(conn, keys, trigger)
        assert len(alerts(conn, "R1")) == 1
        # An offline capture can create its own R1, without touching live state.
        for number in range(9, 13):
            evaluate(conn, keys, packet(number, 8000 + number, domain="offline:file"))
        assert len(alerts(conn, "R1", "offline:file")) == 1
        assert len(alerts(conn, "R1")) == 1


def test_r1_rearms_on_window_membership_without_cooldown(config, keys):
    with transaction(config) as conn:
        for number in range(1, 6):
            evaluate(conn, keys, packet(number, 8000 + number, number - 1))
        assert evaluate(conn, keys, packet(6, 8001, 5)) == []
        trigger = packet(7, 8006, time_us=START + 31 * SECOND + 1)
        evaluate(conn, keys, trigger)
        rows = alerts(conn, "R1")
        assert len(rows) == 2
        assert_alert(rows[1], "R1", trigger,
                     ["capture:3", "capture:4", "capture:5", "capture:6", "capture:7"])


@pytest.mark.parametrize("extra_us,expected", [(0, 1), (1, 0)])
def test_r2_sixty_second_boundary_and_unknown_attempted_username(config, keys, extra_us, expected):
    with transaction(config) as conn:
        values = [app(number, number - 1, username="never-registered") for number in range(1, 5)]
        for value in values:
            assert evaluate(conn, keys, value) == []
        trigger = app(5, username="never-registered", time_us=START + 60 * SECOND + extra_us)
        emitted = evaluate(conn, keys, trigger)
        rows = alerts(conn, "R2")
        assert len(rows) == expected
        assert emitted == ([rows[0]["id"]] if expected else [])
        if expected:
            assert_alert(rows[0], "R2", trigger, [value["event_id"] for value in values] + [trigger["event_id"]])


def test_r2_excludes_untrusted_or_irrelevant_failures(config, keys):
    with transaction(config) as conn:
        for number in range(1, 5):
            evaluate(conn, keys, app(number))
        bad = app(5)
        insert(conn, keys, bad, valid=False)
        assert rules.evaluate_event(conn, keys, "live", bad["event_id"]) == []
        tampered = app(6)
        insert(conn, keys, tampered)
        conn.execute("UPDATE events SET outcome='login_denied' WHERE event_id=?", (tampered["event_id"],))
        conn.execute("UPDATE events SET username='alice' WHERE event_id=?", (tampered["event_id"],))
        assert rules.evaluate_event(conn, keys, "live", tampered["event_id"]) == []
        irrelevant = [app(7, username="alice"), app(8, src_ip="172.29.0.11"),
                      app(9, kind="admin_login_failure", outcome="console_login_denied"),
                      app(10, kind="blocked_request", outcome="blocked_request"),
                      app(11, outcome="malformed_form"), app(12, src_ip="unknown")]
        for value in irrelevant:
            assert evaluate(conn, keys, value) == []
        assert alerts(conn) == []
        trigger = app(13)
        evaluate(conn, keys, trigger)
        assert_alert(alerts(conn, "R2")[0], "R2", trigger,
                     [app(n)["event_id"] for n in (1, 2, 3, 4, 13)])
        for number in range(20, 25):
            assert evaluate(conn, keys, app(number, src_ip="unknown")) == []
        assert len(alerts(conn, "R2")) == 1


def test_r2_rearms_and_retains_latest_five_in_deterministic_order(config, keys):
    with transaction(config) as conn:
        failures(conn, keys)
        assert evaluate(conn, keys, app(6, 5)) == []
        trigger = app(7, time_us=START + 61 * SECOND + 1)
        evaluate(conn, keys, trigger)
        rows = alerts(conn, "R2")
        assert len(rows) == 2
        assert_alert(rows[1], "R2", trigger, [app(n)["event_id"] for n in (3, 4, 5, 6, 7)])


def test_replay_ignores_later_ingested_events_and_future_timestamps(config, keys):
    with transaction(config) as conn:
        early = [app(number) for number in range(1, 5)]
        for value in early:
            insert(conn, keys, value)
        insert(conn, keys, app(5))
        assert rules.evaluate_event(conn, keys, "live", early[-1]["event_id"]) == []
        future = packet(1, 8001, 1)
        insert(conn, keys, future)
        for number in range(2, 6):
            insert(conn, keys, packet(number, 8000 + number))
        assert rules.evaluate_event(conn, keys, "live", "capture:5") == []
        assert alerts(conn) == []


@pytest.mark.parametrize("extra_us,expected", [(0, 1), (1, 0), (-120 * SECOND - 1, 0)])
def test_r3_success_boundary_at_120_seconds_after_r2(config, keys, extra_us, expected):
    with transaction(config) as conn:
        values = failures(conn, keys)
        r2 = alerts(conn, "R2")[0]
        trigger = success(6, 124, time_us=START + 124 * SECOND + extra_us)
        evaluate(conn, keys, trigger)
        rows = alerts(conn, "R3")
        assert len(rows) == expected
        if expected:
            data = json.loads(rows[0]["evidence_json"])
            assert data["alert_ids"] == [r2["id"]]
            assert set(data["event_ids"]) == {v["event_id"] for v in values} | {trigger["event_id"]}
            assert rows[0]["session_ref"] == "session-a"
            assert rows[0]["dedup_key"] == trigger["event_id"]


def test_r3_uses_latest_matching_r2_and_verified_storage_success(config, keys):
    with transaction(config) as conn:
        failures(conn, keys)
        evaluate(conn, keys, app(6, 5))
        evaluate(conn, keys, app(7, time_us=START + 61 * SECOND + 1))
        latest = alerts(conn, "R2")[-1]
        for value in [success(8, 62, src_ip="172.29.0.11"), success(9, 62, username="alice"),
                      app(10, 62, kind="admin_login_success", outcome="console_login_ok", session_ref="admin-session"),
                      app(11, 62, kind="login_success", outcome="login_ok", session_ref=None)]:
            assert evaluate(conn, keys, value) == []
        forged = success(12, 62)
        insert(conn, keys, forged, valid=False)
        assert rules.evaluate_event(conn, keys, "live", forged["event_id"]) == []
        trigger = success(13, 62)
        evaluate(conn, keys, trigger)
        assert len(alerts(conn, "R3")) == 1
        assert json.loads(alerts(conn, "R3")[0]["evidence_json"])["alert_ids"] == [latest["id"]]


def test_r4_requires_verified_authenticated_foreign_denial(config, keys):
    with transaction(config) as conn:
        for value in [app(1, kind="blocked_request", outcome="blocked_request"),
                      app(2, kind="record_read", outcome="record_read", session_ref="session-a", record_id="alice-record"),
                      app(3, kind="foreign_record_denied", outcome="foreign_record_denied", session_ref=None, record_id="alice-record"),
                      app(4, kind="foreign_record_denied", outcome="foreign_record_denied", session_ref="session-a", record_id=None),
                      app(5, kind="foreign_record_denied", outcome="foreign_record_denied", session_ref="session-a", record_id="alice-record", username=None),
                      app(6, kind="foreign_record_denied", outcome="missing_record", session_ref="session-a", record_id="alice-record"),
                      denial(9, 0, src_ip="unknown")]:
            assert evaluate(conn, keys, value) == []
        forged = denial(7, 0)
        insert(conn, keys, forged, valid=False)
        assert rules.evaluate_event(conn, keys, "live", forged["event_id"]) == []
        trigger = denial(8, 0)
        emitted = evaluate(conn, keys, trigger)
        row = alerts(conn, "R4")[0]
        assert emitted == [row["id"]]
        assert_alert(row, "R4", trigger, [trigger["event_id"]])


@pytest.mark.parametrize("extra_us,expected", [(0, 1), (1, 0), (-300 * SECOND - 1, 0)])
def test_r5_login_window_and_complete_linked_evidence(config, keys, extra_us, expected):
    with transaction(config) as conn:
        values = failures(conn, keys)
        login = success(6, 5)
        evaluate(conn, keys, login)
        trigger = denial(7, 305, time_us=START + 305 * SECOND + extra_us)
        evaluate(conn, keys, trigger)
        rows = alerts(conn, "R5")
        assert len(rows) == expected
        if expected:
            linked = [alerts(conn, rule)[0]["id"] for rule in ("R2", "R3", "R4")]
            assert_alert(rows[0], "R5", trigger,
                         [v["event_id"] for v in values] + [login["event_id"], trigger["event_id"]],
                         dedup="session-a", linked=linked)
            assert rows[0]["session_ref"] == "session-a"


def test_r5_source_username_session_isolation_and_once_per_session(config, keys):
    with transaction(config) as conn:
        failures(conn, keys)
        evaluate(conn, keys, success(6, 5))
        for value in [app(7, 6, kind="foreign_record_denied", outcome="foreign_record_denied", record_id="alice-record", session_ref="session-b"),
                      denial(8, 6, src_ip="172.29.0.11"), denial(9, 6, username="alice")]:
            evaluate(conn, keys, value)
        assert alerts(conn, "R5") == []
        first = denial(10, 7)
        evaluate(conn, keys, first)
        original = alerts(conn, "R5")[0]
        evaluate(conn, keys, denial(11, 8))
        assert alerts(conn, "R5") == [original]
        assert len(alerts(conn, "R4")) == 5


def test_reopen_keys_and_connections_do_not_duplicate_persisted_findings(config, keys):
    with transaction(config) as conn:
        failures(conn, keys)
        evaluate(conn, keys, success(6, 5))
        trigger = denial(7, 6)
        emitted = evaluate(conn, keys, trigger)
        original = alerts(conn)
        assert len(emitted) == 2 and len(original) == 4
    restored_keys = load_or_create_keys(config)
    with transaction(config) as conn:
        assert rules.evaluate_event(conn, restored_keys, "live", trigger["event_id"]) == []
        assert alerts(conn) == original


def test_app_hook_creates_alert_in_callers_uncommitted_transaction(config, keys):
    with closing(connect(config)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for number in range(1, 6):
            append_app_event(conn, keys, app(number))
        assert len(alerts(conn, "R2")) == 1
        assert conn.in_transaction
        with closing(connect(config)) as observer:
            assert observer.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
            assert alerts(observer) == []
        conn.rollback()
    with closing(connect(config)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert alerts(conn) == []


def test_app_hook_only_evaluates_new_insertions_and_failure_rolls_back(config, keys, monkeypatch):
    value = app(1)
    with transaction(config) as conn:
        insert(conn, keys, value)

    def fail_after_finding(conn, supplied_keys, domain, event_id):
        assert conn.in_transaction and supplied_keys is keys and domain == "live"
        assert conn.execute("SELECT 1 FROM events WHERE event_id=?", (event_id,)).fetchone()
        conn.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                     ("partial", "live", "R2", SOURCE, "bob", None, START,
                      event_id, "warning", "partial finding", '{"event_ids":[],"alert_ids":[]}', event_id))
        raise RuntimeError("forced rule evaluation failure")

    monkeypatch.setattr(rules, "evaluate_event", fail_after_finding)
    with transaction(config) as conn:
        assert append_app_event(conn, keys, value) == value["event_id"]
        assert alerts(conn) == []
    with pytest.raises(RuntimeError, match="forced rule evaluation failure"):
        with transaction(config) as conn:
            append_app_event(conn, keys, app(2))
    with closing(connect(config)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert alerts(conn) == []

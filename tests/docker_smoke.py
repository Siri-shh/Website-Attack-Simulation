"""Independent HTTPS acceptance client; never imports application internals.

Run the ordinary phase once on fresh/aged login evidence. --retain-block leaves
this client's reviewed block for a controller-managed restart. Afterwards run
--verify-restart with the same --state file to check persistence and unblock.
The state file contains public record evidence and IDs, never cookies/passwords.
"""

import argparse
import base64
from datetime import datetime
from decimal import Decimal
from html import unescape
from html.parser import HTMLParser
import json
import math
from pathlib import Path
import re
import time
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import requests


ALICE_ID = "00000000000000000000000000000002"
CLIENT_IP = "172.29.0.10"
SERVER_IP = "172.29.0.20"


class SmokeFailure(RuntimeError):
    pass


def check(condition, message):
    if not condition:
        raise SmokeFailure(message)


class CsrfParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrf_token":
            self.tokens.append(attrs.get("value", ""))


def csrf(html):
    parser = CsrfParser()
    parser.feed(html)
    check(parser.tokens and all(parser.tokens) and len(set(parser.tokens)) == 1,
          "Missing or ambiguous CSRF form token")
    return parser.tokens[0]


def detail_evidence(html):
    """Extract full displayed evidence for persisted-version comparisons."""
    values = re.findall(r'<pre class="evidence-value">([^<]*)</pre>', html)
    times = re.findall(r'<time datetime="([^"]+)">', html)
    sizes = re.findall(r'<dd>(\d+) bytes</dd>', html)
    durations = re.findall(r'<td>(\d+\.\d{6}) ms</td>', html)
    version = re.search(r'Record · version (\d+)', html)
    check(len(values) == 4 and len(times) == 3 and len(sizes) == 3
          and len(durations) == 3 and version is not None,
          "Incomplete record evidence/timestamp/timing presentation")
    cipher, nonce, digest, signature = [unescape(value) for value in values]
    try:
        cipher_bytes = base64.b64decode(cipher, validate=True)
        nonce_bytes = base64.b64decode(nonce, validate=True)
        signature_bytes = base64.b64decode(signature, validate=True)
        instants = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in times]
    except (ValueError, TypeError) as exc:
        raise SmokeFailure("Invalid complete crypto evidence or UTC timestamp") from exc
    check(len(nonce_bytes) == 12 and len(signature_bytes) == 64
          and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
          "Invalid nonce/signature/hash sizes")
    check(all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value)
              for value in times), "Timestamps must include microseconds and UTC")
    check(instants[0] <= instants[1] == instants[2], "Record timestamp ordering changed")
    check(len(cipher_bytes) == int(sizes[1]) == int(sizes[0]) + 16
          and int(sizes[2]) > len(cipher_bytes), "Displayed input/envelope sizes disagree")
    check(all(Decimal(value) >= 0 for value in durations)
          and html.count('class="timing-track"') == 3,
          "Missing measured durations or timing bars")
    check("Digital signature verification passed" in html
          and "Envelope hash verification passed" in html,
          "Record evidence is not reported verified")
    return {"version": int(version.group(1)), "ciphertext_b64": cipher,
            "nonce_b64": nonce, "sha256_hex": digest, "signature_b64": signature,
            "times": times, "sizes": [int(value) for value in sizes],
            "durations_ms": durations}


def assert_cascade(alerts, events, *, source, denied_record):
    """Check linked findings against actual signed HTTP outcome observations."""
    by_rule = {alert["rule"]: alert for alert in alerts}
    check(set(by_rule) == {"R2", "R3", "R4", "R5"}, "Missing new R2–R5 findings")
    r2, r3, r4, r5 = [by_rule[rule] for rule in ("R2", "R3", "R4", "R5")]
    for alert in by_rule.values():
        check(alert["domain"] == "live" and alert["src_ip"] == source
              and alert["username"] == "bob", "Alert identity differs from HTTP actor")
        ids = alert["evidence"]["event_ids"]
        check(ids and len(ids) == len(set(ids)) and alert["trigger_event_id"] in ids
              and set(ids) <= set(events), "Alert evidence cannot be resolved")
        for event_id in ids:
            event = events[event_id]
            check(event["signature_valid"] is True and event["domain"] == "live"
                  and event["src_ip"] == source and event["username"] == "bob",
                  "Cascade evidence is not a valid signed event for Bob")
    failure_ids = set(r2["evidence"]["event_ids"])
    check(len(failure_ids) == 5 and all(events[item]["kind"] == "login_failure"
          and events[item]["outcome"] == "login_denied" for item in failure_ids),
          "R2 does not reference five actual failed logins")
    login = events[r3["trigger_event_id"]]
    denied = events[r4["trigger_event_id"]]
    check(login["kind"] == "login_success" and login["outcome"] == "login_ok"
          and login["session_ref"], "R3 does not reference actual successful login")
    check(denied["kind"] == denied["outcome"] == "foreign_record_denied"
          and denied["record_id"] == denied_record, "R4 does not reference actual denial")
    session = login["session_ref"]
    check(denied["session_ref"] == session
          and all(alert["session_ref"] == session for alert in (r3, r4, r5)),
          "R3–R5 are not bound to the successful session")
    check(set(r3["evidence"]["event_ids"]) == failure_ids | {login["event_id"]}
          and r3["evidence"]["alert_ids"] == [r2["id"]]
          and r4["evidence"]["event_ids"] == [denied["event_id"]]
          and set(r5["evidence"]["event_ids"]) == failure_ids | {login["event_id"], denied["event_id"]}
          and set(r5["evidence"]["alert_ids"]) == {r2["id"], r3["id"], r4["id"]}
          and r5["trigger_event_id"] == denied["event_id"], "Cascade linkage is incomplete")
    failure_times = [events[item]["time_us"] for item in failure_ids]
    check(max(failure_times) - min(failure_times) <= 60_000_000
          and 0 <= login["time_us"] - r2["time_us"] <= 120_000_000
          and 0 <= denied["time_us"] - login["time_us"] <= 300_000_000,
          "Cascade observations exceed the documented rule windows")
    return by_rule


class Client:
    def __init__(self, base, ca, timeout):
        self.base = base.rstrip("/") + "/"
        self.ca = ca
        self.timeout = timeout
        self.session = requests.Session()

    def request(self, method, route, **kwargs):
        target = urljoin(self.base, route.lstrip("/"))
        check(urlsplit(target).netloc == urlsplit(self.base).netloc
              and urlsplit(target).scheme == "https", "Request escaped HTTPS service")
        return self.session.request(method, target, verify=self.ca, timeout=self.timeout,
                                    allow_redirects=False, **kwargs)

    def page(self, route):
        response = self.request("GET", route)
        check(response.status_code == 200, "Expected ordinary authenticated page")
        return response.text

    def login(self, username, password, expected=303):
        token = csrf(self.page("/login"))
        response = self.request("POST", "/login", data={
            "username": username, "password": password, "csrf_token": token})
        check(response.status_code == expected, "Unexpected credential POST outcome")
        return response

    def snapshot(self):
        response = self.request("GET", "/api/snapshot")
        check(response.status_code == 200, "Admin snapshot unavailable")
        result = response.json()
        check(result["domain"] == "live", "Snapshot did not select live evidence")
        check(result["capture"]["state"] == "running" and not result["capture"]["error"],
              "Capture is not healthy")
        return result

    def block(self, source):
        response = self.request("POST", "/blocks", data={"ip": source,
            "reason": "T20 reviewed smoke evidence", "csrf_token": csrf(self.page("/"))})
        check(response.status_code == 303, "Manual admin block failed")

    def unblock(self, source):
        response = self.request("POST", f"/blocks/{source}/remove",
                                data={"csrf_token": csrf(self.page("/"))})
        check(response.status_code == 303, "Manual admin unblock failed")

    def close(self):
        self.session.close()


def poll(admin, timeout, predicate, events):
    deadline = time.monotonic() + timeout
    while True:
        current = admin.snapshot()
        events.update((event["event_id"], event) for event in current["events"])
        if predicate(current):
            return current
        remaining = deadline - time.monotonic()
        check(remaining > 0, "Timed out waiting for actual evidence")
        time.sleep(min(0.25, remaining))


def check_r1(snapshot):
    events = {event["event_id"]: event for event in snapshot["events"]}
    for alert in snapshot["alerts"]:
        if alert["rule"] != "R1" or alert["src_ip"] != CLIENT_IP:
            continue
        ids = alert["evidence"]["event_ids"]
        if not set(ids) <= set(events):
            continue
        evidence = [events[item] for item in ids]
        if ({event["dst_port"] for event in evidence} != {8443, 8444, 8001, 8002, 8003}
                or any(event["kind"] != "connection_attempt" or event["src_ip"] != CLIENT_IP
                       or event["dst_ip"] != SERVER_IP or event["signature_valid"] is not None
                       or not event["capture_id"] or event["frame_number"] <= 0 for event in evidence)):
            continue
        check(len({event["capture_id"] for event in evidence}) == 1
              and max(event["time_us"] for event in evidence)
              - min(event["time_us"] for event in evidence) <= 30_000_000,
              "R1 evidence is not one bounded actual capture")
        return alert["id"]
    raise SmokeFailure("No resolvable actual five-port R1; perform controller preflight/probe first")


def ordinary(args, bob, alice, admin):
    baseline = admin.snapshot()
    check(not any(block["ip"] == CLIENT_IP for block in baseline["blocks"]),
          "Client source already blocked; existing state requires controller review")
    r1_id = check_r1(baseline)
    baseline_alerts = {alert["id"] for alert in baseline["alerts"]}
    baseline_events = {event["event_id"] for event in baseline["events"]}
    events = {event["event_id"]: event for event in baseline["events"]}
    alice.login("alice", "AliceDemo!2026")
    alice_html = alice.page(f"/records/{ALICE_ID}")
    alice_evidence = detail_evidence(alice_html)
    for index in range(5):
        bob.login("bob", f"T20-wrong-password-{index}", expected=401)
    bob.login("bob", "BobDemo!2026")
    denied = bob.request("GET", f"/records/{ALICE_ID}")
    check(denied.status_code == 403, "Foreign record request was not denied")
    for value in ("Alice's record", "Alice's ordinary demonstration record.",
                  *(alice_evidence[key] for key in ("ciphertext_b64", "nonce_b64", "sha256_hex", "signature_b64"))):
        check(value not in denied.text and value not in bob.page("/"),
              "Foreign owner plaintext or crypto evidence leaked")

    def found(current):
        return {alert["rule"] for alert in current["alerts"]
                if alert["id"] not in baseline_alerts and alert["username"] == "bob"
                and alert["src_ip"] == CLIENT_IP} >= {"R2", "R3", "R4", "R5"}

    current = poll(admin, args.wait_timeout, found, events)
    new_alerts = [alert for alert in current["alerts"] if alert["id"] not in baseline_alerts
                  and alert["rule"] in {"R2", "R3", "R4", "R5"}
                  and alert["username"] == "bob" and alert["src_ip"] == CLIENT_IP]
    by_rule = assert_cascade(new_alerts, events, source=CLIENT_IP, denied_record=ALICE_ID)
    event_ids = set().union(*(set(alert["evidence"]["event_ids"]) for alert in new_alerts))
    check(not event_ids & baseline_events, "Old events satisfied the new smoke cascade")
    check(all(events[item]["dst_ip"] == SERVER_IP and events[item]["dst_port"] == 8443
              for item in event_ids), "Signed outcomes have incorrect server identity")

    marker = uuid4().hex
    response = bob.request("POST", "/records/new", data={"title": f"T20 {marker}",
        "body": "Ordinary smoke record", "csrf_token": csrf(bob.page("/records/new"))})
    check(response.status_code == 303, "Normal record creation failed")
    route = response.headers.get("Location", "")
    check(re.fullmatch(r"/records/[0-9a-f]{32}", route) is not None, "Unexpected created record route")
    record_id = route.rsplit("/", 1)[1]
    created = detail_evidence(bob.page(route))
    check(created["version"] == 1 and detail_evidence(bob.page(route)) == created,
          "Created evidence changed on refresh")
    response = bob.request("POST", route + "/edit", data={"title": f"T20 edited {marker}",
        "body": "Edited ordinary smoke record", "csrf_token": csrf(bob.page(route + "/edit"))})
    check(response.status_code == 303 and response.headers.get("Location") == route,
          "Normal record edit failed")
    edited = detail_evidence(bob.page(route))
    check(edited["version"] == 2 and edited["times"][0] == created["times"][0]
          and edited["times"][1] > created["times"][1]
          and all(edited[key] != created[key] for key in
                  ("nonce_b64", "ciphertext_b64", "sha256_hex", "signature_b64"))
          and detail_evidence(bob.page(route)) == edited, "Edited evidence was not persisted")

    admin.block(CLIENT_IP)
    block_owned = True
    try:
        check(bob.request("GET", route).status_code == 403, "Existing Bob cookie bypassed manual block")
        admin.page("/")
        current = poll(admin, args.wait_timeout,
                       lambda snap: any(event["kind"] == "blocked_request"
                                        and event["src_ip"] == CLIENT_IP and event["username"] == "bob"
                                        for event in snap["events"]), events)
        check(any(block["ip"] == CLIENT_IP for block in current["blocks"]), "Manual block not saved")
        blocked = next(event for event in current["events"] if event["kind"] == "blocked_request"
                       and event["src_ip"] == CLIENT_IP and event["username"] == "bob")
        check(blocked["signature_valid"] is True
              and blocked["session_ref"] == events[by_rule["R3"]["trigger_event_id"]]["session_ref"],
              "Blocked existing session did not produce valid signed evidence")
        admin.unblock(CLIENT_IP)
        block_owned = False
        check(detail_evidence(bob.page(route)) == edited, "Existing cookie did not recover after unblock")
        check(not any(block["ip"] == CLIENT_IP for block in admin.snapshot()["blocks"]),
              "Unblock did not remove saved block")
        if args.retain_block:
            admin.block(CLIENT_IP)
            block_owned = True
            check(bob.request("GET", route).status_code == 403, "Retained restart block ineffective")
        state = {"schema": 1, "source_ip": CLIENT_IP, "record_id": record_id,
                 "record_evidence": edited, "retained_block": args.retain_block,
                 "alert_ids": {rule: alert["id"] for rule, alert in by_rule.items()},
                 "trigger_ids": {rule: alert["trigger_event_id"] for rule, alert in by_rule.items()},
                 "event_ids": sorted(event_ids), "r1_id": r1_id}
        Path(args.state).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    except Exception:
        if block_owned:
            admin.unblock(CLIENT_IP)
        raise
    print(f"PASS record {record_id} version 2; create/edit/refresh and manual block/unblock")
    print(f"PASS R1 alert {r1_id}")
    for rule in ("R2", "R3", "R4", "R5"):
        print(f"PASS {rule} alert {by_rule[rule]['id']} trigger {by_rule[rule]['trigger_event_id']}")
    print("PASS cascade events " + ",".join(sorted(event_ids)))
    print("PASS public restart evidence saved; retained block " + str(args.retain_block))


def verify_restart(args, bob, admin):
    state = json.loads(Path(args.state).read_text(encoding="utf-8"))
    check(state["schema"] == 1 and state["retained_block"] is True
          and state["source_ip"] == CLIENT_IP, "State does not describe a deliberately retained block")
    current = admin.snapshot()
    check(any(block["ip"] == CLIENT_IP and block["created_by"] == "admin"
              for block in current["blocks"]), "Retained block did not survive restart")
    check(bob.request("GET", "/login").status_code == 403, "Restart lost storage admission block")
    alerts = {alert["id"]: alert for alert in current["alerts"]}
    for rule, alert_id in state["alert_ids"].items():
        check(alert_id in alerts and alerts[alert_id]["rule"] == rule
              and alerts[alert_id]["trigger_event_id"] == state["trigger_ids"][rule],
              "Saved alert/trigger identities did not survive restart")
    admin.page("/")
    admin.unblock(CLIENT_IP)
    bob.login("bob", "BobDemo!2026")
    actual = detail_evidence(bob.page(f"/records/{state['record_id']}"))
    check(actual == state["record_evidence"], "Record crypto/timestamps/timings changed across restart")
    check(not any(block["ip"] == CLIENT_IP for block in admin.snapshot()["blocks"]),
          "Restart check did not restore unblocked state")
    print(f"PASS restart record {state['record_id']}; evidence/timings/alerts/block preserved; admin unblocked")


def positive_timeout(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Wait timeout must be a number") from exc
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError("Wait timeout must be finite and between 0 and 60 seconds")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--console-url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--wait-timeout", type=positive_timeout, default=10.0)
    parser.add_argument("--state", default="/tmp/storage-smoke-evidence.json")
    parser.add_argument("--retain-block", action="store_true")
    parser.add_argument("--verify-restart", action="store_true")
    args = parser.parse_args(argv)
    clients = []
    try:
        for value in (args.url, args.console_url):
            parsed = urlsplit(value)
            check(parsed.scheme == "https" and parsed.hostname and not parsed.username
                  and not parsed.password and parsed.path in ("", "/")
                  and not parsed.query and not parsed.fragment, "Service URLs must be HTTPS origins")
        check(args.url.rstrip("/") != args.console_url.rstrip("/"), "Websites require separate origins")
        check(Path(args.ca).is_file(), "Public CA file is missing")
        check(not (args.verify_restart and args.retain_block), "Restart verification cannot retain another block")
        clients = [Client(args.url, args.ca, min(5.0, args.wait_timeout)),
                   Client(args.url, args.ca, min(5.0, args.wait_timeout)),
                   Client(args.console_url, args.ca, min(5.0, args.wait_timeout))]
        bob, alice, admin = clients
        admin.login("admin", "AdminDemo!2026")
        if args.verify_restart:
            verify_restart(args, bob, admin)
        else:
            ordinary(args, bob, alice, admin)
        return 0
    except (SmokeFailure, requests.RequestException, OSError, ValueError, KeyError, TypeError):
        # Never print exception text that may contain request URLs, bodies or cookies.
        print("FAIL HTTPS smoke check; inspect controller evidence and current runtime state")
        return 1
    finally:
        for client in clients:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())

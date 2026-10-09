"""Optional ordinary HTTPS/TCP helpers for the storage security lab."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
import math
import socket
import sys
import time
from urllib.parse import quote

import requests

_HTTP_TIMEOUT = 1.0


class _CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input" or self.token is not None:
            return
        values = {name.lower(): value for name, value in attrs}
        if values.get("name") == "csrf_token" and values.get("value") is not None:
            self.token = values["value"]


def extract_csrf(html: str) -> str:
    """Extract the first input value named csrf_token from login HTML."""
    parser = _CsrfParser()
    parser.feed(html)
    parser.close()
    if parser.token is None:
        raise ValueError("login page did not contain a csrf_token input")
    return parser.token


def _finite_float(value: str, name: str, *, minimum: float = 0.0, strictly_positive: bool = False) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"{name} must be a finite number") from exc
    if not math.isfinite(number) or (number <= minimum if strictly_positive else number < minimum):
        qualifier = "positive" if strictly_positive else "at least zero"
        raise argparse.ArgumentTypeError(f"{name} must be finite and {qualifier}")
    return number


def _delay_arg(value: str) -> float:
    return _finite_float(value, "delay")


def _timeout_arg(value: str) -> float:
    return _finite_float(value, "timeout", strictly_positive=True)


def _limit_arg(value: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("limit must be an integer from 1 to 1000") from exc
    if not 1 <= result <= 1000:
        raise argparse.ArgumentTypeError("limit must be an integer from 1 to 1000")
    return result


def _ports_arg(value: str) -> list[int]:
    try:
        parts = value.split(",")
        ports = [int(part.strip()) for part in parts]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ports must be comma-separated integers from 1 to 65535") from exc
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be comma-separated integers from 1 to 65535")
    return ports


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send explicit ordinary requests to a lab target")
    commands = parser.add_subparsers(dest="command", required=True)
    attempts = commands.add_parser("login-attempts", help="try bounded password-file candidates")
    attempts.add_argument("--url", required=True, help="storage base URL, for example https://host:8443")
    attempts.add_argument("--username", required=True)
    attempts.add_argument("--password-file", required=True)
    attempts.add_argument("--limit", type=_limit_arg, default=5)
    attempts.add_argument("--delay", type=_delay_arg, default=0.0)
    attempts.add_argument("--ca", help="CA certificate path; system trust is used when omitted")

    record = commands.add_parser("request-record", help="log in and GET one supplied record")
    record.add_argument("--url", required=True, help="storage base URL")
    record.add_argument("--username", required=True)
    record.add_argument("--password", required=True)
    record.add_argument("--record-id", required=True)
    record.add_argument("--ca", help="CA certificate path; system trust is used when omitted")

    probe = commands.add_parser("probe", help="connect to only the explicit host and ports")
    probe.add_argument("--host", required=True)
    probe.add_argument("--ports", required=True, type=_ports_arg)
    probe.add_argument("--timeout", type=_timeout_arg, default=1.0)
    return parser


def _base_url(value: str) -> str:
    return value.rstrip("/")


def _verify(ca: str | None) -> str | bool:
    return ca if ca else True


def _get_csrf(session: requests.Session, login_url: str, verify: str | bool) -> str:
    response = session.get(login_url, verify=verify, timeout=_HTTP_TIMEOUT)
    if response.status_code != 200:
        raise RuntimeError(f"login page returned HTTP {response.status_code}")
    return extract_csrf(response.text)


def _login_post(session: requests.Session, login_url: str, username: str, password: str,
                csrf: str, verify: str | bool) -> requests.Response:
    return session.post(
        login_url,
        data={"username": username, "password": password, "csrf_token": csrf},
        allow_redirects=False,
        verify=verify,
        timeout=_HTTP_TIMEOUT,
    )


def _login_attempts(args: argparse.Namespace) -> int:
    try:
        with open(args.password_file, "r", encoding="utf-8") as source:
            passwords = [line.rstrip("\r\n") for line in source]
    except (OSError, UnicodeError) as exc:
        print(f"Could not read password file: {exc}", file=sys.stderr)
        return 2
    candidates = passwords[:args.limit]
    if not candidates:
        print("Password file has no candidates", file=sys.stderr)
        return 2

    session = requests.Session()
    login_url = _base_url(args.url) + "/login"
    verify = _verify(args.ca)
    for index, password in enumerate(candidates, start=1):
        try:
            csrf = _get_csrf(session, login_url, verify)
            response = _login_post(session, login_url, args.username, password, csrf, verify)
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            print(f"Attempt {index}: request error ({type(exc).__name__})", file=sys.stderr)
            return 1
        status = response.status_code
        if status == 401:
            outcome = "credentials rejected; continuing"
        elif status == 303:
            outcome = "login succeeded; stopping"
        elif status == 403:
            outcome = "blocked; stopping"
        else:
            print(f"Attempt {index}: HTTP {status}; unexpected response", file=sys.stderr)
            return 1
        print(f"Attempt {index}: HTTP {status}; {outcome}")
        if status in (303, 403):
            return 0
        if index < len(candidates) and args.delay:
            time.sleep(args.delay)
    return 0


def _request_record(args: argparse.Namespace) -> int:
    session = requests.Session()
    base = _base_url(args.url)
    login_url = base + "/login"
    verify = _verify(args.ca)
    try:
        csrf = _get_csrf(session, login_url, verify)
        login = _login_post(session, login_url, args.username, args.password, csrf, verify)
        print(f"Login: HTTP {login.status_code}")
        if login.status_code != 303:
            print("Login did not succeed; record request skipped", file=sys.stderr)
            return 1
        record_url = base + "/records/" + quote(args.record_id, safe="")
        response = session.get(record_url, verify=verify, timeout=_HTTP_TIMEOUT)
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"Request error ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(f"Record request: HTTP {response.status_code}")
    return 0 if 200 <= response.status_code < 400 else 1


def _probe(args: argparse.Namespace) -> int:
    failures = 0
    for port in args.ports:
        connection = None
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.settimeout(args.timeout)
            status = connection.connect_ex((args.host, port))
        except OSError as exc:
            print(f"{args.host}:{port}: connection error ({type(exc).__name__})")
            failures += 1
            continue
        finally:
            if connection is not None:
                connection.close()
        outcome = "open" if status == 0 else "closed or unreachable"
        print(f"{args.host}:{port}: {outcome}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    """Run one explicitly targeted external-client command."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    if args.command == "login-attempts":
        return _login_attempts(args)
    if args.command == "request-record":
        return _request_record(args)
    if args.command == "probe":
        return _probe(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

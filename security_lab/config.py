"""Configuration and shared time/address helpers."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import shutil
import time
from typing import Mapping


@dataclass(frozen=True)
class Config:
    data_dir: Path = Path("data").resolve()
    bind_host: str = "127.0.0.1"
    server_ip: str = "127.0.0.1"
    storage_port: int = 8443
    console_port: int = 8444
    capture_interface: str | None = None
    tshark_path: str = "tshark"
    tls_names: tuple[str, ...] = ("localhost", "127.0.0.1")


def _default_tshark() -> str:
    found = shutil.which("tshark")
    if found:
        return str(Path(found).resolve())
    if os.name == "nt":
        candidate = Path("C:/Program Files/Wireshark/tshark.exe")
        if candidate.is_file():
            return str(candidate.resolve())
    # The monitor reports missing tooling as a health condition.
    return "tshark"


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer port") from exc
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def _ip(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, default)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"{name} must be an IP literal") from exc


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    env = os.environ if environ is None else environ
    data_dir = Path(env.get("LAB_DATA_DIR", "data")).expanduser().resolve()
    bind_host = _ip(env, "LAB_BIND_HOST", "127.0.0.1")
    server_ip = _ip(env, "LAB_SERVER_IP", "127.0.0.1")
    storage_port = _port(env, "LAB_STORAGE_PORT", 8443)
    console_port = _port(env, "LAB_CONSOLE_PORT", 8444)
    if storage_port == console_port:
        raise ValueError("storage and console ports must be distinct")

    interface = env.get("LAB_CAPTURE_INTERFACE")
    if interface == "":
        interface = None

    if "LAB_TSHARK" in env:
        configured_tshark = env["LAB_TSHARK"].strip()
        executable = Path(configured_tshark).expanduser()
        if not configured_tshark or not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("LAB_TSHARK must name an existing executable")
        tshark_path = str(executable.resolve())
    else:
        tshark_path = _default_tshark()

    raw_names = env.get("LAB_TLS_NAMES")
    if raw_names is None:
        names = ("localhost", "127.0.0.1", server_ip)
    else:
        names = tuple(part.strip() for part in raw_names.split(","))
    if not names or any(not name for name in names):
        raise ValueError("LAB_TLS_NAMES must contain nonempty names")
    tls_names = tuple(dict.fromkeys(names))

    return Config(
        data_dir=data_dir,
        bind_host=bind_host,
        server_ip=server_ip,
        storage_port=storage_port,
        console_port=console_port,
        capture_interface=interface,
        tshark_path=tshark_path,
        tls_names=tls_names,
    )


def utc_us() -> int:
    return time.time_ns() // 1_000


def format_utc(value_us: int) -> str:
    instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value_us)
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def format_ist(value_us: int) -> str:
    instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value_us)
    return instant.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat(
        timespec="microseconds"
    )


def normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)

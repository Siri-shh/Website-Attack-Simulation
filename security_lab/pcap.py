"""Content-addressed, chronologically ordered offline packet analysis."""

from contextlib import closing
import hashlib
from pathlib import Path
import subprocess

from .capture import TSHARK_FIELDS
from .db import connect
from .packets import PacketParseError, insert_packet, parse_packet_fields


class PcapAnalysisError(RuntimeError):
    """The input capture could not be read, decoded or imported."""


def _file_digest(path):
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1_048_576), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PcapAnalysisError(f"Cannot read capture file: {exc}") from exc
    return digest.hexdigest()


def _alert_count(config, domain):
    with closing(connect(config)) as conn:
        return conn.execute("SELECT count(*) FROM alerts WHERE domain=?", (domain,)).fetchone()[0]


def analyze_pcap(config, keys, path, *, process_runner=None) -> dict:
    """Return newly inserted events/alerts; replay retains existing offline findings."""
    source = Path(path)
    digest = _file_digest(source)
    domain = "offline:" + digest
    argv = [config.tshark_path, "-n", "-r", str(source), "-T", "fields",
            "-E", "header=n", "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n"]
    for field in TSHARK_FIELDS:
        argv.extend(("-e", field))
    runner = process_runner or subprocess.run
    try:
        result = runner(argv, stdin=subprocess.DEVNULL, capture_output=True,
                        text=True, encoding="utf-8", errors="strict", shell=False, check=False)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise PcapAnalysisError(f"Capture decoding failed: {exc}") from exc
    if result.returncode != 0:
        detail = str(result.stderr or "").strip()[-2_048:]
        raise PcapAnalysisError(f"Capture decoding failed (exit {result.returncode})" +
                                (f": {detail}" if detail else ""))
    if not isinstance(result.stdout, str):
        raise PcapAnalysisError("Capture decoder returned invalid packet metadata")
    # A live/growing capture is not a stable content-addressed offline input.
    if _file_digest(source) != digest:
        raise PcapAnalysisError("Capture file changed during decoding; analyze a stopped capture")
    events = []
    try:
        for line in result.stdout.splitlines():
            event = parse_packet_fields(line, capture_id=digest, domain=domain,
                                        server_ip=config.server_ip)
            if event is not None:
                events.append(event)
    except PacketParseError as exc:
        raise PcapAnalysisError(f"Malformed capture packet metadata: {exc}") from exc
    events.sort(key=lambda event: (event["time_us"], event["frame_number"]))
    before = _alert_count(config, domain)
    inserted = 0
    try:
        for event in events:
            inserted += int(insert_packet(config, keys, event))
    except Exception as exc:
        # Earlier atomic observations remain recoverable by an idempotent retry.
        raise PcapAnalysisError(f"Capture packet import failed: {exc}") from exc
    return {"domain": domain, "inserted_events": inserted,
            "alert_count": _alert_count(config, domain) - before}

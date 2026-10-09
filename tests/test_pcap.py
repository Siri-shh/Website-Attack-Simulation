"""Offline replay contracts with injected finite TShark field output."""

from contextlib import closing
from dataclasses import replace
import hashlib
import json
import subprocess

import pytest

from security_lab.capture import TSHARK_FIELDS
from security_lab.console import snapshot
from security_lab.db import connect, transaction
from security_lab.packets import insert_packet, parse_packet_fields
from security_lab.pcap import PcapAnalysisError, analyze_pcap


def row(number, port, epoch="1700000000.123456"):
    return "\t".join(map(str, (number, epoch, "172.29.0.10", "", "172.29.0.20", "",
                                 40000 + number, port, 1, 0, 100 + number, "")))


class Decoder:
    def __init__(self, lines=(), *, code=0, stderr=""):
        self.output = "\n".join(lines) + ("\n" if lines else "")
        self.code = code
        self.stderr = stderr
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, self.code, self.output, self.stderr)


@pytest.fixture
def capture_file(tmp_path):
    # Bytes define identity; decoded rows are simulated, not a real capture claim.
    source = tmp_path / "capture with spaces; literal.pcapng"
    source.write_bytes(b"\x0a\x0d\x0d\x0a simulated capture fixture")
    return source


def test_import_hash_domain_r1_and_duplicate_replay_leave_live_unchanged(config, keys, capture_file):
    cfg = replace(config, server_ip="172.29.0.20")
    live = parse_packet_fields(row(1, 8443), capture_id="existing-live", domain="live", server_ip=cfg.server_ip)
    insert_packet(cfg, keys, live)
    health = {"state": "running", "started_at_us": 10, "last_packet_at_us": 20,
              "capture_path": "existing.pcapng", "error": None}
    with transaction(cfg) as conn:
        conn.execute("INSERT INTO status(key,value_json) VALUES('capture',?)", (json.dumps(health),))
        conn.execute("INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES(?,?,?,?)",
                     ("172.29.0.10", 1, "admin", "retained block"))
    before = snapshot(cfg, keys)
    digest = hashlib.sha256(capture_file.read_bytes()).hexdigest()
    domain = "offline:" + digest
    decoder = Decoder([row(number, port) for number, port in enumerate(range(8001, 8006), 1)])

    first = analyze_pcap(cfg, keys, capture_file, process_runner=decoder)
    second = analyze_pcap(cfg, keys, capture_file, process_runner=decoder)

    assert first == {"domain": domain, "inserted_events": 5, "alert_count": 1}
    assert second == {"domain": domain, "inserted_events": 0, "alert_count": 0}
    after = snapshot(cfg, keys)
    assert {key: value for key, value in after.items() if key != "domains"} == {
        key: value for key, value in before.items() if key != "domains"
    }
    assert set(after["domains"]) == {"live", domain}
    offline = snapshot(cfg, keys, domain)
    assert [item["rule"] for item in offline["alerts"]] == ["R1"]
    assert all(item["kind"] == "connection_attempt" and item["signature_valid"] is None
               and item["capture_id"] == digest for item in offline["events"])
    assert offline["capture"] == health and offline["blocks"] == before["blocks"]


def test_offline_rows_sort_by_original_time_then_frame(config, keys, capture_file):
    cfg = replace(config, server_ip="172.29.0.20")
    decoder = Decoder([row(9, 8009, "1700000002"), row(5, 8005, "1700000001"),
                       row(2, 8002, "1700000001")])
    result = analyze_pcap(cfg, keys, capture_file, process_runner=decoder)
    with closing(connect(cfg)) as conn:
        ordered = [(item[0], item[1]) for item in conn.execute(
            "SELECT frame_number,time_us FROM events WHERE domain=? ORDER BY seq", (result["domain"],)
        )]
    assert ordered == [(2, 1_700_000_001_000_000), (5, 1_700_000_001_000_000),
                       (9, 1_700_000_002_000_000)]


def test_decoder_uses_literal_path_and_shared_fields_without_shell(config, keys, capture_file):
    decoder = Decoder()
    result = analyze_pcap(config, keys, capture_file, process_runner=decoder)
    argv, kwargs = decoder.calls[0]
    assert argv[0] == config.tshark_path
    assert argv[argv.index("-r") + 1] == str(capture_file)
    assert "-n" in argv and argv[argv.index("-T") + 1] == "fields"
    assert tuple(argv[index + 1] for index, value in enumerate(argv) if value == "-e") == TSHARK_FIELDS
    assert "-w" not in argv and "-i" not in argv
    assert kwargs.get("shell", False) is False
    assert result["inserted_events"] == result["alert_count"] == 0


@pytest.mark.parametrize("decoder", [Decoder(code=2, stderr="Not a capture file"),
                                     Decoder([row(1, 8001), "invalid metadata"])])
def test_malformed_capture_is_explicit_and_inserts_nothing(config, keys, capture_file, decoder):
    cfg = replace(config, server_ip="172.29.0.20")
    with pytest.raises(PcapAnalysisError, match="(?i)(capture|packet)"):
        analyze_pcap(cfg, keys, capture_file, process_runner=decoder)
    with closing(connect(cfg)) as conn:
        assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM status").fetchone()[0] == 0


def test_missing_input_is_explicit_without_starting_decoder(config, keys, tmp_path):
    decoder = Decoder()
    with pytest.raises(PcapAnalysisError, match="(?i)capture"):
        analyze_pcap(config, keys, tmp_path / "missing.pcapng", process_runner=decoder)
    assert not decoder.calls

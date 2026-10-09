"""TShark packet field normalization and database insertion."""

from decimal import Decimal, InvalidOperation
import json

from .config import normalize_ip
from .db import transaction
from .rules import evaluate_event
class PacketParseError(ValueError):
    """Raised when a TShark metadata row is malformed."""


def parse_packet_fields(line: str, *, capture_id: str, domain: str, server_ip: str) -> dict | None:
    """Normalize one tab-separated TShark row; return None when irrelevant."""
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) != 12:
        raise PacketParseError("Expected exactly twelve TShark fields")

    (frame_text, epoch_text, src4, src6, dst4, dst6, src_port_text,
     dst_port_text, syn_text, ack_text, seq_text, retrans_text) = fields

    def integer(value: str, name: str) -> int:
        try:
            if not value or value.strip() != value:
                raise ValueError
            return int(value, 10)
        except (TypeError, ValueError) as exc:
            raise PacketParseError(f"Invalid {name}") from exc

    frame_number = integer(frame_text, "frame number")
    if frame_number <= 0:
        raise PacketParseError("Invalid frame number")

    try:
        epoch = Decimal(epoch_text)
        if not epoch.is_finite():
            raise InvalidOperation
        time_us = int(epoch * 1_000_000)
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise PacketParseError("Invalid packet timestamp") from exc

    # Non-TCP rows have empty TCP columns. Missing fields make them irrelevant;
    # malformed present numbers are errors so the capture worker can report them.
    if not src_port_text or not dst_port_text or not syn_text or not ack_text or not seq_text:
        return None

    src_port = integer(src_port_text, "source port")
    dst_port = integer(dst_port_text, "destination port")
    def boolean_flag(value: str, name: str) -> bool:
        if value in ("1", "True"):
            return True
        if value in ("0", "False"):
            return False
        raise PacketParseError(f"Invalid {name}")

    syn = boolean_flag(syn_text, "SYN flag")
    ack = boolean_flag(ack_text, "ACK flag")
    tcp_seq_raw = integer(seq_text, "TCP sequence number")
    if not retrans_text:
        retransmission = False
    else:
        retransmission = boolean_flag(retrans_text, "retransmission flag")

    source_text = src4 or src6
    destination_text = dst4 or dst6
    if not source_text or not destination_text or not 1 <= src_port <= 65535 or not 1 <= dst_port <= 65535:
        return None
    try:
        src_ip = normalize_ip(source_text)
        dst_ip = normalize_ip(destination_text)
        configured_server = normalize_ip(server_ip)
    except (TypeError, ValueError):
        return None
    if dst_ip != configured_server or syn != 1 or ack != 0:
        return None
    if not isinstance(capture_id, str) or not capture_id or not isinstance(domain, str) or not domain:
        raise PacketParseError("Capture ID and domain must be nonempty strings")

    return {
        "domain": domain,
        "event_id": f"{capture_id}:{frame_number}",
        "time_us": time_us,
        "kind": "connection_attempt",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "username": None,
        "session_ref": None,
        "record_id": None,
        "outcome": "observed",
        "signature_b64": None,
        "capture_id": capture_id,
        "frame_number": frame_number,
        "src_port": src_port,
        "tcp_seq_raw": tcp_seq_raw,
        "retransmission": retransmission,
    }


def insert_packet(config, keys, event: dict) -> bool:
    """Persist and evaluate one normalized packet observation atomically."""
    metadata = ("domain", "event_id", "time_us", "kind", "src_ip", "dst_ip",
                "dst_port", "username", "session_ref", "record_id", "outcome",
                "signature_b64", "capture_id", "frame_number", "src_port", "tcp_seq_raw",
                "retransmission")
    if not isinstance(event, dict) or any(field not in event for field in metadata):
        raise PacketParseError("Packet event is missing normalized fields")
    if (event["kind"] != "connection_attempt" or event["outcome"] != "observed"
            or event["signature_b64"] is not None
            or type(event["time_us"]) is not int
            or type(event["frame_number"]) is not int or event["frame_number"] <= 0
            or type(event["dst_port"]) is not int or not 1 <= event["dst_port"] <= 65535
            or type(event["src_port"]) is not int or not 1 <= event["src_port"] <= 65535
            or type(event["tcp_seq_raw"]) is not int
            or type(event["retransmission"]) is not bool
            or not isinstance(event["capture_id"], str) or not event["capture_id"]
            or not isinstance(event["domain"], str) or not event["domain"]
            or not isinstance(event["event_id"], str)):
        raise PacketParseError("Invalid normalized packet event")
    try:
        src_ip = normalize_ip(event["src_ip"])
        dst_ip = normalize_ip(event["dst_ip"])
    except (TypeError, ValueError) as exc:
        raise PacketParseError("Invalid packet address") from exc
    payload = {
        "capture_id": event["capture_id"],
        "frame_number": event["frame_number"],
        "src_port": event["src_port"],
        "tcp_seq_raw": event["tcp_seq_raw"],
        "retransmission": event["retransmission"],
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with transaction(config) as conn:
        # A repeated frame is identified by event_id; retransmissions can have a
        # different frame number, so compare the persisted flow tuple and sequence.
        existing = conn.execute(
            "SELECT event_id,payload_json FROM events "
            "WHERE domain=? AND capture_id=? AND src_ip=? AND dst_ip=? AND dst_port=?",
            (event["domain"], event["capture_id"], src_ip, dst_ip, event["dst_port"]),
        ).fetchall()
        for row in existing:
            try:
                old = json.loads(row["payload_json"])
            except (TypeError, ValueError):
                continue
            if (old.get("src_port") == event["src_port"]
                    and old.get("tcp_seq_raw") == event["tcp_seq_raw"]):
                return False
        cursor = conn.execute(
            "INSERT INTO events(domain,event_id,time_us,kind,src_ip,dst_ip,dst_port,username,"
            "session_ref,record_id,outcome,payload_json,signature_b64,capture_id,frame_number) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(domain,event_id) DO NOTHING",
            (event["domain"], event["event_id"], event["time_us"], event["kind"], src_ip, dst_ip,
             event["dst_port"], None, None, None, event["outcome"], payload_json, None,
             event["capture_id"], event["frame_number"]),
        )
        if cursor.rowcount != 1:
            return False
        evaluate_event(conn, keys, event["domain"], event["event_id"])
        return True

"""Contract tests for packet metadata parsing and idempotent insertion."""

import pytest

from security_lab.packets import PacketParseError, insert_packet, parse_packet_fields
from security_lab.db import connect


SERVER = "172.29.0.20"
SOURCE = "172.29.0.10"
EPOCH = "1700000000.123456"


def row(*, number=1, epoch=EPOCH, src=SOURCE, dst=SERVER, srcport=40100,
        dstport=8443, syn="1", ack="0", seq=100, retrans="0",
        src6="", dst6=""):
    """Produce all twelve fields in the frozen TShark order."""
    return "\t".join(map(str, (number, epoch, src, src6, dst, dst6, srcport,
                                  dstport, syn, ack, seq, retrans)))


def parsed(line, *, capture="cap-a", domain="live", server=SERVER):
    return parse_packet_fields(line, capture_id=capture, domain=domain, server_ip=server)


def test_parse_ipv4_incoming_syn_and_decimal_epoch_microseconds():
    event = parsed(row())

    assert event["event_id"] == "cap-a:1"
    assert event["domain"] == "live"
    assert event["time_us"] == 1_700_000_000_123_456
    assert event["kind"] == "connection_attempt"
    assert event["src_ip"] == SOURCE and event["dst_ip"] == SERVER
    assert event["dst_port"] == 8443
    assert event["outcome"] == "observed"
    assert event["signature_b64"] is None
    assert event["capture_id"] == "cap-a" and event["frame_number"] == 1
    assert event["src_port"] == 40100 and event["tcp_seq_raw"] == 100
    assert event["retransmission"] is False


def test_parse_ipv6_incoming_syn():
    event = parsed(
        row(src="", dst="", src6="2001:db8::10", dst6="2001:db8::20"),
        server="2001:db8::20",
    )
    assert event["src_ip"] == "2001:db8::10"
    assert event["dst_ip"] == "2001:db8::20"


@pytest.mark.parametrize(
    "syn,ack,retrans",
    [
        ("1", "0", "0"),
        ("True", "False", "False"),
        ("1", "False", "False"),
        ("True", "0", "0"),
    ],
)
def test_numeric_and_tshark_text_flags_normalize_identically(syn, ack, retrans):
    event = parsed(row(syn=syn, ack=ack, retrans=retrans))
    assert event == parsed(row())


@pytest.mark.parametrize("syn,ack", [("True", "True"), ("False", "False")])
def test_text_true_ack_or_false_syn_is_ignored(syn, ack):
    assert parsed(row(syn=syn, ack=ack)) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"syn": "2"},
        {"ack": "Yes"},
        {"retrans": "maybe"},
    ],
)
def test_malformed_present_tshark_flags_raise(changes):
    with pytest.raises(PacketParseError):
        parsed(row(**changes))


@pytest.mark.parametrize(
    "line,server",
    [
        (row(ack="1"), SERVER),                         # ACK without SYN
        (row(src=SERVER, dst=SOURCE, dstport=40100), SERVER),  # outgoing
        (row(dst="172.29.0.21"), SERVER),              # other destination
    ],
)
def test_irrelevant_packet_rows_are_ignored(line, server):
    assert parsed(line, server=server) is None


@pytest.mark.parametrize("line", [
    row() + "\textra",                                # wrong field count
    row(epoch="not-a-number"),
    row(number="not-a-frame"),
    row(srcport="not-a-port"),
])
def test_malformed_fields_raise_packet_parse_error(line):
    with pytest.raises(PacketParseError):
        parsed(line)


def test_duplicate_frame_and_syn_retransmission_insert_once(config, keys):
    original = parsed(row(number=1, seq=777))
    retransmission = parsed(row(number=2, seq=777, retrans="1"))

    assert insert_packet(config, keys, original) is True
    assert insert_packet(config, keys, original) is False
    assert insert_packet(config, keys, retransmission) is False

    with connect(config) as conn:
        stored = conn.execute(
            "SELECT event_id,capture_id,frame_number FROM events WHERE kind='connection_attempt'"
        ).fetchall()
    assert [(item["event_id"], item["capture_id"], item["frame_number"]) for item in stored] == [
        ("cap-a:1", "cap-a", 1)
    ]


def test_textual_syn_retransmission_is_deduplicated(config, keys):
    original = parsed(row(number=10, seq=909, retrans="False"))
    retransmission = parsed(row(number=11, seq=909, retrans="True"))

    assert insert_packet(config, keys, original) is True
    assert insert_packet(config, keys, retransmission) is False


def test_five_distinct_server_ports_create_actual_r1(config, keys):
    for index, port in enumerate((8001, 8002, 8003, 8004, 8005), start=1):
        event = parsed(row(number=index, dstport=port, seq=1000 + index))
        assert insert_packet(config, keys, event) is True

    with connect(config) as conn:
        alerts = conn.execute("SELECT rule,domain FROM alerts ORDER BY rule").fetchall()
    assert [(item["rule"], item["domain"]) for item in alerts] == [("R1", "live")]

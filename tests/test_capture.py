"""Simulated process contracts; no TShark or real subprocess is launched."""

from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
from queue import Queue
import subprocess
from threading import Event, Lock
import time
import uuid

import pytest

from security_lab.capture import CaptureWorker, TSHARK_FIELDS
from security_lab.db import connect


class FakeStream:
    def __init__(self):
        self.lines = Queue()
        self.remainder = ""
        self.closed = False
        self.read_count = 0

    def feed(self, line):
        self.lines.put(line)

    def readline(self, size=-1):
        line = self.remainder or self.lines.get(timeout=5)
        if size > 0 and len(line) > size:
            self.remainder = line[size:]
            line = line[:size]
        else:
            self.remainder = ""
        self.read_count += 1
        return line

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, *, stubborn=False):
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.returncode = None
        self.finished = Event()
        self.lock = Lock()
        self.stubborn = stubborn
        self.terminated = 0
        self.killed = 0
        self.waited = 0

    def poll(self):
        return self.returncode

    def finish(self, code):
        with self.lock:
            if self.returncode is None:
                self.returncode = code
                self.stdout.feed("")
                self.stderr.feed("")
                self.finished.set()

    def wait(self, timeout=None):
        self.waited += 1
        if self.stubborn and timeout is not None and self.returncode is None:
            raise subprocess.TimeoutExpired("fake-tshark", timeout)
        if not self.finished.wait(timeout=timeout):
            raise subprocess.TimeoutExpired("fake-tshark", timeout)
        return self.returncode

    def terminate(self):
        self.terminated += 1
        if not self.stubborn:
            self.finish(0)

    def kill(self):
        self.killed += 1
        self.finish(-9)


class ProcessFactory:
    def __init__(self, process=None, error=None):
        self.process = process or FakeProcess()
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error:
            raise self.error
        self.path = Path(argv[argv.index("-w") + 1])
        self.path.write_bytes(b"fake capture retained")
        return self.process


def eventually(predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if predicate():
            return
        Event().wait(0.01)
    assert predicate(), "Timed out waiting for fake process supervision"


def capture_config(config):
    return replace(config, capture_interface="adapter with spaces", server_ip="172.29.0.20",
                   tshark_path="C:/tools with spaces/tshark.exe")


def row(number, port, epoch="1700000000.123456"):
    return "\t".join(map(str, (number, epoch, "172.29.0.10", "", "172.29.0.20", "",
                                 40000 + number, port, 1, 0, 100 + number, ""))) + "\n"


def persisted_health(config):
    with closing(connect(config)) as conn:
        stored = conn.execute("SELECT value_json FROM status WHERE key='capture'").fetchone()
    return json.loads(stored[0])


def counts(config):
    with closing(connect(config)) as conn:
        return (conn.execute("SELECT count(*) FROM events").fetchone()[0],
                conn.execute("SELECT count(*) FROM alerts WHERE rule='R1' AND domain='live'").fetchone()[0])


def test_idle_running_command_is_owned_and_persisted(config, keys):
    cfg = capture_config(config)
    factory = ProcessFactory()
    worker = CaptureWorker(cfg, keys, process_factory=factory, clock=lambda: 123456)
    try:
        worker.start()
        worker.start()  # no second process while resources are owned
        argv, kwargs = factory.calls[0]
        assert len(factory.calls) == 1
        assert argv[0] == cfg.tshark_path
        assert argv[argv.index("-i") + 1] == cfg.capture_interface
        assert "-n" in argv and "-l" in argv and "-P" in argv
        assert argv[argv.index("-T") + 1] == "fields"
        assert tuple(argv[index + 1] for index, value in enumerate(argv) if value == "-e") == TSHARK_FIELDS
        assert "-f" not in argv and "-Y" not in argv
        assert kwargs.get("shell", False) is False
        assert kwargs["stdout"] == subprocess.PIPE and kwargs["stderr"] == subprocess.PIPE
        assert kwargs["text"] is True
        status = worker.health()
        assert status == {"state": "running", "started_at_us": 123456,
                          "last_packet_at_us": None, "capture_path": str(factory.path), "error": None}
        assert persisted_health(cfg) == status
        assert factory.path.parent == cfg.data_dir / "captures"
        assert factory.path.suffix == ".pcapng"
        uuid.UUID(factory.path.stem)
    finally:
        worker.stop()


@pytest.mark.parametrize("missing_interface", [False, True])
def test_startup_failure_is_explicit_and_persistent(config, keys, missing_interface):
    cfg = capture_config(config)
    if missing_interface:
        cfg = replace(cfg, capture_interface=None)
    factory = ProcessFactory(error=FileNotFoundError("tshark executable missing"))
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    worker.start()
    assert worker.health()["state"] == "degraded"
    assert worker.health()["error"]
    assert persisted_health(cfg) == worker.health()
    assert len(factory.calls) == (0 if missing_interface else 1)
    worker.stop()


def test_stdout_rows_create_real_packets_and_r1(config, keys):
    cfg = capture_config(config)
    factory = ProcessFactory()
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    try:
        worker.start()
        for number, port in enumerate((8001, 8002, 8003, 8004, 8005), start=1):
            factory.process.stdout.feed(row(number, port))
        eventually(lambda: counts(cfg) == (5, 1))
        assert worker.health()["last_packet_at_us"] == 1_700_000_000_123_456
        with closing(connect(cfg)) as conn:
            stored = conn.execute("SELECT capture_id,signature_b64 FROM events ORDER BY seq").fetchall()
        assert {item["capture_id"] for item in stored} == {factory.path.stem}
        assert all(item["signature_b64"] is None for item in stored)
    finally:
        worker.stop()


def test_informational_stderr_is_drained_and_exit_is_degraded(config, keys):
    cfg = capture_config(config)
    factory = ProcessFactory()
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    try:
        worker.start()
        factory.process.stderr.feed("Capturing on adapter\n")
        eventually(lambda: factory.process.stderr.read_count >= 1)
        assert worker.health()["state"] == "running"
        factory.process.stderr.feed("Permission denied\n")
        factory.process.finish(2)
        eventually(lambda: worker.health()["state"] == "degraded")
        assert "2" in worker.health()["error"]
        assert "Permission denied" in worker.health()["error"]
        assert persisted_health(cfg) == worker.health()
    finally:
        worker.stop()


def test_bad_row_is_reported_without_stopping_ingestion(config, keys):
    cfg = capture_config(config)
    factory = ProcessFactory()
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    try:
        worker.start()
        factory.process.stdout.feed("bad fields\n")
        factory.process.stdout.feed(row(1, 8443))
        eventually(lambda: counts(cfg)[0] == 1)
        assert worker.health()["state"] == "degraded"
        assert "packet" in worker.health()["error"].lower()
        assert factory.process.poll() is None
    finally:
        worker.stop()


def test_timestamp_regression_warns_and_preserves_packet_times(config, keys):
    cfg = capture_config(config)
    factory = ProcessFactory()
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    try:
        worker.start()
        factory.process.stdout.feed(row(1, 8443, "1700000001.000001"))
        factory.process.stdout.feed(row(2, 8444, "1700000000.000002"))
        eventually(lambda: counts(cfg)[0] == 2)
        assert worker.health()["state"] == "degraded"
        assert "timestamp" in worker.health()["error"].lower()
        with closing(connect(cfg)) as conn:
            times = [item[0] for item in conn.execute("SELECT time_us FROM events ORDER BY seq")]
        assert times == [1_700_000_001_000_001, 1_700_000_000_000_002]
    finally:
        worker.stop()


@pytest.mark.parametrize("stubborn", [False, True])
def test_stop_reaps_only_owned_process_and_preserves_capture(config, keys, stubborn):
    cfg = capture_config(config)
    owned = FakeProcess(stubborn=stubborn)
    unrelated = FakeProcess()
    factory = ProcessFactory(owned)
    worker = CaptureWorker(cfg, keys, process_factory=factory)
    worker.start()
    capture_path = worker.health()["capture_path"]
    worker.stop()
    worker.stop()
    assert owned.terminated == 1 and owned.waited >= 1
    assert owned.killed == (1 if stubborn else 0)
    assert owned.stdout.closed and owned.stderr.closed
    assert unrelated.terminated == unrelated.killed == unrelated.waited == 0
    assert Path(capture_path).read_bytes() == b"fake capture retained"
    assert worker.health()["state"] == "stopped"
    assert worker.health()["capture_path"] == capture_path
    assert persisted_health(cfg) == worker.health()

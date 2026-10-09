"""Owned TShark process with bounded, concurrent live metadata supervision."""

import json
from pathlib import Path
import subprocess
from threading import Event, RLock, Thread, current_thread
import time
import uuid

from .config import utc_us
from .db import transaction
from .packets import PacketParseError, insert_packet, parse_packet_fields


TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.seq_raw",
    "tcp.analysis.retransmission",
)
_MAX_LINE = 16_384
_MAX_ERROR = 2_048
_SHUTDOWN_TIMEOUT = 2.0


class CaptureWorker:
    """Capture live connection observations without assuming host bridge access."""

    def __init__(self, config, keys, *, process_factory=None, clock=utc_us):
        self.config = config
        self.keys = keys
        self._process_factory = process_factory or subprocess.Popen
        self._clock = clock
        self._lifecycle = RLock()
        self._lock = RLock()
        self._process = None
        self._threads = ()
        self._stopping = Event()
        self._stderr_tail = ""
        self._last_timestamp = None
        self._capture_id = None
        self._status = {
            "state": "stopped", "started_at_us": None, "last_packet_at_us": None,
            "capture_path": None, "error": None,
        }

    def health(self) -> dict:
        with self._lock:
            return dict(self._status)

    def _publish(self, **changes):
        # Serialize status writes with packet processing and lifecycle changes.
        with self._lock:
            self._status.update(changes)
            payload = json.dumps(self._status, sort_keys=True, separators=(",", ":"))
            with transaction(self.config) as conn:
                conn.execute(
                    "INSERT INTO status(key,value_json) VALUES('capture',?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                    (payload,),
                )

    def _degrade(self, message):
        with self._lock:
            if not self._stopping.is_set():
                self._publish(state="degraded", error=str(message)[-_MAX_ERROR:])

    def start(self):
        with self._lifecycle:
            # An exited process remains owned until stop reaps and joins it.
            if self._process is not None:
                return
            self._stopping.clear()
            self._stderr_tail = ""
            self._last_timestamp = None
            self._capture_id = uuid.uuid4().hex
            capture_path = Path(self.config.data_dir) / "captures" / (self._capture_id + ".pcapng")
            self._publish(state="starting", started_at_us=self._clock(),
                          last_packet_at_us=None, capture_path=str(capture_path), error=None)
            if not self.config.capture_interface:
                self._degrade("Capture interface is not configured")
                return
            argv = [
                self.config.tshark_path, "-n", "-l", "-i", self.config.capture_interface,
                "-w", str(capture_path), "-F", "pcapng", "-P", "-T", "fields",
                "-E", "header=n", "-E", "separator=/t", "-E", "occurrence=f",
                "-E", "quote=n",
            ]
            for field in TSHARK_FIELDS:
                argv.extend(("-e", field))
            try:
                capture_path.parent.mkdir(parents=True, exist_ok=True)
                process = self._process_factory(
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                    bufsize=1, shell=False,
                )
            except OSError as exc:
                self._degrade(f"Capture startup failed: {exc}")
                return
            self._process = process
            self._publish(state="running")
            self._threads = (
                Thread(target=self._read_stdout, args=(process,), name="capture-stdout", daemon=True),
                Thread(target=self._read_stderr, args=(process,), name="capture-stderr", daemon=True),
                Thread(target=self._watch_exit, args=(process,), name="capture-exit", daemon=True),
            )
            started = []
            try:
                for thread in self._threads:
                    thread.start()
                    started.append(thread)
            except RuntimeError as exc:
                self._threads = tuple(started)
                self.stop()
                self._publish(state="degraded", error=f"Capture supervision startup failed: {exc}"[-_MAX_ERROR:])

    @staticmethod
    def _line(stream):
        """Read one bounded line and discard oversized remainders in bounded chunks."""
        line = stream.readline(_MAX_LINE + 1)
        oversized = len(line) > _MAX_LINE
        if oversized and not line.endswith("\n"):
            while True:
                remainder = stream.readline(_MAX_LINE + 1)
                if not remainder or remainder.endswith("\n"):
                    break
        return line, oversized

    def _read_stdout(self, process):
        try:
            while True:
                line, oversized = self._line(process.stdout)
                if not line:
                    break
                if self._stopping.is_set():
                    continue
                if oversized:
                    self._degrade("Malformed packet metadata: line exceeds capture limit")
                    continue
                try:
                    event = parse_packet_fields(
                        line, capture_id=self._capture_id, domain="live", server_ip=self.config.server_ip,
                    )
                    if event is None:
                        continue
                    with self._lock:
                        if self._stopping.is_set():
                            continue
                        regression = (self._last_timestamp is not None
                                      and event["time_us"] < self._last_timestamp)
                        self._last_timestamp = event["time_us"]
                        insert_packet(self.config, self.keys, event)
                        changes = {"last_packet_at_us": event["time_us"]}
                        if regression:
                            changes.update(state="degraded", error="Packet timestamp regression observed")
                        self._publish(**changes)
                except PacketParseError as exc:
                    self._degrade(f"Malformed packet metadata: {exc}")
                except Exception as exc:
                    self._degrade(f"Packet ingestion failed: {exc}")
        except Exception as exc:
            self._degrade(f"Capture stdout failed: {exc}")
        finally:
            process.stdout.close()

    def _read_stderr(self, process):
        try:
            while True:
                line, oversized = self._line(process.stderr)
                if not line:
                    break
                with self._lock:
                    self._stderr_tail = (self._stderr_tail + line)[-_MAX_ERROR:]
                    if oversized:
                        self._stderr_tail = (self._stderr_tail + " [truncated]")[-_MAX_ERROR:]
        except Exception as exc:
            self._degrade(f"Capture stderr failed: {exc}")
        finally:
            process.stderr.close()

    def _watch_exit(self, process):
        try:
            code = process.wait()
            # Preserve queued packet metadata and final stderr before reporting exit.
            deadline = time.monotonic() + _SHUTDOWN_TIMEOUT
            for thread in self._threads[:2]:
                thread.join(max(0, deadline - time.monotonic()))
            with self._lock:
                detail = self._stderr_tail.strip()
                self._degrade(f"Capture process exited with code {code}" + (f": {detail}" if detail else ""))
        except Exception as exc:
            self._degrade(f"Capture process supervision failed: {exc}")

    def stop(self):
        with self._lifecycle:
            self._stopping.set()
            process = self._process
            if process is None:
                self._publish(state="stopped")
                return
            failure = None
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=_SHUTDOWN_TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=_SHUTDOWN_TIMEOUT)
            except (OSError, subprocess.TimeoutExpired) as exc:
                failure = f"Capture shutdown failed: {exc}"
            deadline = time.monotonic() + _SHUTDOWN_TIMEOUT
            for thread in self._threads:
                if thread is not current_thread():
                    thread.join(max(0, deadline - time.monotonic()))
            if any(thread.is_alive() for thread in self._threads) or process.poll() is None:
                failure = failure or "Capture shutdown incomplete; owned resources remain"
            if failure:
                self._publish(state="degraded", error=failure[-_MAX_ERROR:])
                return
            # Readers close their pipes after EOF; capture files are never deleted.
            self._process = None
            self._threads = ()
            self._publish(state="stopped")

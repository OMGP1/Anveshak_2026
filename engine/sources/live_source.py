"""Passive local capture -> bounded metadata queue. No transmitting operations.

dumpcap owns capture privileges. Only its stdout pipe enters the engine; raw
packet bytes are discarded after metadata extraction and never written to disk.
"""
from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import time

from engine.decode.packet import parse_packet

SNAPLEN = 4096
QUEUE_CAPACITY = 4096
PCAP_FORMATS = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
                b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
LINK_TYPES = {0, 1, 12, 101, 108, 113, 228}


def process_options() -> dict:
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def capture_setup_hint() -> str:
    if sys.platform == "darwin":
        return ("macOS: run 'brew install wireshark' for dumpcap. Capture permission requires "
                "'brew install --cask wireshark-chmodbpf' (administrator approval, then reboot). "
                "Restart the API from a new terminal. If using SIH_DUMPCAP, set it to the executable "
                "path in the API's environment, not only the attack-lab terminal. Do not run the API as root.")
    return "Install Wireshark/dumpcap (and Npcap on Windows), or set SIH_DUMPCAP in the API's environment."


def capture_binary() -> str:
    configured = os.environ.get("SIH_DUMPCAP")
    if configured:
        path = Path(configured).expanduser()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"SIH_DUMPCAP={configured!r} is not an executable file. " + capture_setup_hint())
        return str(path.resolve())
    candidates = [shutil.which("dumpcap"), r"C:\Program Files\Wireshark\dumpcap.exe",
                  "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
                  "/opt/homebrew/bin/dumpcap", "/usr/local/bin/dumpcap"]
    for path in candidates:
        if path and Path(path).is_file() and os.access(path, os.X_OK):
            return str(Path(path).resolve())
    raise RuntimeError("dumpcap was not found. " + capture_setup_hint())


def local_interface(name: str) -> bool:
    # Never allow dumpcap's remote TCP/RPCAP sources, pipes, or stdin.
    return bool(name and name != "-" and not name.startswith("-")
                and ":" not in name and "@" not in name and "/" not in name
                and ("\\" not in name or name.startswith("\\Device\\NPF_")))


def interfaces() -> dict:
    try:
        binary = capture_binary()
        result = subprocess.run([binary, "-D"], capture_output=True, text=True, errors="replace",
                                timeout=5, **process_options())
        if result.returncode:
            raise RuntimeError(result.stderr.strip()[:1000] or "Unable to list capture interfaces")
        items = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\d+\.\s+(\S+)(?:\s+\((.*)\))?\s*$", line)
            if match and local_interface(match[1]):
                items.append({"id": match[1], "name": match[2] or match[1]})
        if not items:
            raise RuntimeError("No local capture interfaces are available.")
        return {"available": True, "interfaces": items, "error": None, "backend": "dumpcap"}
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        message = str(exc)
        if sys.platform == "darwin" and capture_setup_hint() not in message:
            message += " " + capture_setup_hint()
        return {"available": False, "interfaces": [], "error": message, "backend": "dumpcap"}


def read_exact(stream, length: int, *, allow_eof: bool = False) -> bytes:
    data = bytearray()
    while len(data) < length:
        part = stream.read(length - len(data))
        if not part:
            if allow_eof and not data:
                return b""
            raise ValueError("Truncated capture stream")
        data.extend(part)
    return bytes(data)


def packet_records(stream):
    header = read_exact(stream, 24)
    if header[:4] not in PCAP_FORMATS:
        raise ValueError("Live capture requires classic PCAP framing")
    endian, factor = PCAP_FORMATS[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= SNAPLEN or linktype not in LINK_TYPES:
        raise ValueError("Unsupported capture version, snapshot length, or link type")
    yield None  # Valid global header: capture is ready, even on a quiet link.
    while True:
        record = read_exact(stream, 16, allow_eof=True)
        if not record:
            return
        sec, subsec, caplen, wirelen = struct.unpack(endian + "IIII", record)
        if caplen > snaplen or caplen > wirelen or subsec >= 1_000_000_000 // factor:
            raise ValueError("Invalid or oversized capture record")
        raw = read_exact(stream, caplen)
        yield sec * 1_000_000_000 + subsec * factor, raw, linktype, caplen < wirelen


class LiveSource:
    def __init__(self, interface: str, capture_filter: str = "ip", *, capacity: int = QUEUE_CAPACITY,
                 max_queue_age_s: float = 2.0):
        if not local_interface(interface):
            raise ValueError("Only local capture interfaces are accepted")
        if not 1 <= capacity <= 65536 or not 0 < max_queue_age_s <= 30:
            raise ValueError("Invalid capture queue limits")
        if len(capture_filter) > 512 or "\x00" in capture_filter:
            raise ValueError("Capture filter is too long or contains a null character")
        self.interface = interface
        # IPv6 is excluded: the legacy engine hashes IPv6 addresses to IPv4-sized
        # identifiers, which would misrepresent forensic endpoints in live alerts.
        self.capture_filter = f"ip and ({capture_filter or 'ip'})"
        self.queue = queue.Queue(maxsize=capacity)
        self.max_queue_age_s = max_queue_age_s
        self.ready = threading.Event()
        self.done = threading.Event()
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self._process = None
        self._threads = []
        self._stderr = deque(maxlen=16)
        self.error = None
        self.received = self.decoded = self.discarded = self.queue_dropped = self.stale_dropped = 0
        self.truncated = self.timestamp_regressions = 0
        self.decode_ns = 0

    def start(self):
        binary = capture_binary()
        command = [binary, "-i", self.interface, "-f", self.capture_filter, "-s", str(SNAPLEN),
                   "-B", "8", "-P", "-q", "-w", "-"]
        self._process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, bufsize=0, **process_options())
        self._threads = [threading.Thread(target=self._read_stderr, daemon=True),
                         threading.Thread(target=self._read, daemon=True)]
        for thread in self._threads:
            thread.start()
        if not self.ready.wait(5) or self.error:
            self.close()
            message = self.error or "Capture did not become ready within five seconds"
            message += ": " + " ".join(self._stderr) if self._stderr else ""
            if sys.platform == "darwin" and any(word in message.lower() for word in ("permission", "/dev/bpf")):
                message += " " + capture_setup_hint()
            raise RuntimeError(message)
        return self

    def _read_stderr(self):
        try:
            while not self.stopping.is_set():
                part = self._process.stderr.read(1024)
                if not part:
                    return
                self._stderr.append(part.decode("utf-8", errors="replace").strip())
        except (OSError, ValueError):
            pass

    def _read(self):
        last_ns = 0
        try:
            for record in packet_records(self._process.stdout):
                if self.stopping.is_set():
                    break
                if record is None:
                    self.ready.set()
                    continue
                ts_ns, raw, linktype, truncated = record
                received_ns = time.perf_counter_ns()
                if ts_ns < last_ns:
                    self.timestamp_regressions += 1
                last_ns = max(last_ns, ts_ns)
                # Enforce the address-width restriction after decoding too;
                # capture filters alone must not define forensic correctness.
                meta = parse_packet(last_ns, raw, linktype, ipv4_only=True)
                del raw
                with self._lock:
                    self.received += 1
                    self.truncated += int(truncated)
                    self.decode_ns += time.perf_counter_ns() - received_ns
                    if meta is None:
                        self.discarded += 1
                        continue
                    self.decoded += 1
                    try:
                        self.queue.put_nowait((meta, received_ns))
                    except queue.Full:
                        self.queue_dropped += 1
            if not self.stopping.is_set():
                self.error = "Capture process ended unexpectedly"
        except (OSError, ValueError, struct.error) as exc:
            if not self.stopping.is_set():
                self.error = str(exc)
        finally:
            self.done.set()
            self.ready.set()

    def next_packet(self, timeout: float = 0.2):
        deadline = time.monotonic() + timeout
        while not self.stopping.is_set():
            try:
                item = self.queue.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                return None
            if time.perf_counter_ns() - item[1] <= self.max_queue_age_s * 1e9:
                return item
            with self._lock:
                self.stale_dropped += 1
            if time.monotonic() >= deadline:
                return None
        return None

    def stats(self) -> dict:
        with self._lock:
            return {"backend": "dumpcap", "interface": self.interface, "filter": self.capture_filter,
                    "packets_received": self.received, "packets_decoded": self.decoded,
                    "undecodable": self.discarded, "truncated_packets": self.truncated,
                    "queue_depth": self.queue.qsize(), "queue_capacity": self.queue.maxsize,
                    "queue_dropped": self.queue_dropped, "stale_dropped": self.stale_dropped,
                    "kernel_dropped": None, "kernel_drop_note": "Driver drops are not exposed by this PCAP pipe.",
                    "max_queue_age_s": self.max_queue_age_s, "snapshot_bytes": SNAPLEN,
                    "timestamp_regressions": self.timestamp_regressions, "decode_ns": self.decode_ns}

    def close(self):
        self.stopping.set()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        self.done.set()

"""Rust-framed PCAP ingress with the same Python metadata decoder and bounded pipe backpressure."""
from __future__ import annotations

import os
from pathlib import Path
import struct
import subprocess

from engine.decode.packet import parse_packet
from engine.sources.pcap_source import PcapSource

DEFAULT_BINARY = (Path(__file__).resolve().parents[2] / "native/pcap-audit/target/release"
                  / ("pcap-audit.exe" if os.name == "nt" else "pcap-audit"))


class RustPcapSource(PcapSource):
    def __init__(self, path: str, binary: str | None = None) -> None:
        super().__init__(path)
        self.binary = binary or os.environ.get("SIH_RUST_INGEST", str(DEFAULT_BINARY))
        if not Path(self.binary).is_file():
            raise FileNotFoundError("Rust ingest binary is missing; build native/pcap-audit first")

    def __iter__(self):
        self.packets_read = self.packets_yielded = self.non_ip = self.clamped = 0
        process = subprocess.Popen([self.binary, "--stream", self.path], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=65536)
        try:
            header = process.stdout.read(8)
            if len(header) != 8 or header[:4] != b"SIH1":
                raise ValueError("Rust ingest rejected the capture header")
            self.datalink = struct.unpack("!I", header[4:])[0]
            while True:
                header = process.stdout.read(12)
                if not header:
                    break
                if len(header) != 12:
                    raise ValueError("Truncated Rust ingest frame header")
                timestamp, length = struct.unpack("!QI", header)
                if length > 16 * 1024 * 1024:
                    raise ValueError("Rust ingest frame exceeds the memory limit")
                payload = process.stdout.read(length)
                if len(payload) != length:
                    raise ValueError("Truncated Rust ingest frame")
                self.packets_read += 1
                meta = parse_packet(timestamp, payload, self.datalink)
                del payload
                if meta is None:
                    self.non_ip += 1
                else:
                    self.packets_yielded += 1
                    yield meta
            if process.wait(timeout=5) != 0:
                raise ValueError("Rust ingest rejected malformed, truncated, or non-monotonic capture data")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
            process.stderr.close()

    def stats(self) -> dict:
        return {**super().stats(), "backend": "rust-framing-python-metadata"}

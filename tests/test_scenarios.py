from __future__ import annotations

import csv
import json
import os
import sys

import dpkt
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "training")):
    if path not in sys.path:
        sys.path.insert(0, path)

import scenarios as catalogue
from engine.types import ICMP, TCP, THREAT_CLASSES, UDP

IDS = [s["id"] for s in catalogue.SCENARIOS]
SIZE_LIMIT = 5_000_000
SIZE_LIMITS = {"exfil_bulk": 8_000_000}
_PCAP_CACHE: dict[str, list] = {}


def scenario(sid: str) -> dict:
    return catalogue.get(sid)


def read_pcap(sid: str) -> list[tuple[float, bytes]]:
    if sid not in _PCAP_CACHE:
        with open(catalogue.abspath(scenario(sid)["file"]), "rb") as fh:
            _PCAP_CACHE[sid] = list(dpkt.pcap.Reader(fh))
    return _PCAP_CACHE[sid]


def read_flows(sid: str) -> tuple[list[str], list[dict]]:
    with open(catalogue.abspath(scenario(sid)["flow_file"]), "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def test_catalogue_is_complete() -> None:
    assert len(catalogue.SCENARIOS) == 11
    assert len(set(IDS)) == 11
    assert {e["id"] for e in catalogue.EMULATION} == set(IDS)
    for s in catalogue.SCENARIOS:
        assert s["threat_class"] in THREAT_CLASSES
        assert s["proves"]
        assert s["seed"] > 0
        assert s["packets"] > 0
        assert s["duration_s"] > 0


@pytest.mark.parametrize("sid", IDS)
def test_files_exist(sid: str) -> None:
    s = scenario(sid)
    for key in ("file", "flow_file", "labels_file"):
        path = catalogue.abspath(s[key])
        assert os.path.isfile(path), path
        assert os.path.getsize(path) > 0
    assert os.path.getsize(catalogue.abspath(s["file"])) < SIZE_LIMITS.get(sid, SIZE_LIMIT)


@pytest.mark.parametrize("sid", IDS)
def test_pcap_readable_and_timestamps_increase(sid: str) -> None:
    packets = read_pcap(sid)
    assert len(packets) == scenario(sid)["packets"]
    prev = None
    for ts, buf in packets:
        assert len(buf) >= 34
        if prev is not None:
            assert ts > prev
        prev = ts
    span = packets[-1][0] - packets[0][0]
    assert abs(span - scenario(sid)["duration_s"]) < 1.0


@pytest.mark.parametrize("sid", IDS)
def test_pcap_parses_as_ip(sid: str) -> None:
    packets = read_pcap(sid)
    protos = set()
    for _ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        assert isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6))
        assert ip.p in (TCP, UDP, ICMP)
        protos.add(ip.p)
    assert protos


@pytest.mark.parametrize("sid", IDS)
def test_flow_csv_matches_contract(sid: str) -> None:
    columns, rows = read_flows(sid)
    assert columns == catalogue.FLOW_COLUMNS
    assert rows
    assert len(rows) == scenario(sid)["flow_records"]
    packets = read_pcap(sid)
    first, last = packets[0][0], packets[-1][0]
    total = 0
    for row in rows:
        start, end = float(row["ts_start"]), float(row["ts_end"])
        assert first - 1.0 <= start <= end <= last + 1.0
        assert int(row["proto"]) in (TCP, UDP, ICMP)
        assert 0 <= int(row["src_port"]) <= 65535
        assert 0 <= int(row["dst_port"]) <= 65535
        assert int(row["packets"]) >= 1
        assert int(row["bytes"]) >= 20 * int(row["packets"])
        assert 0 <= int(row["tcp_flags"]) <= 0xFF
        assert row["direction_hint"] in ("", "ingress", "egress")
        assert len(row["src_ip"].split(".")) == 4
        assert len(row["dst_ip"].split(".")) == 4
        total += int(row["packets"])
    assert total == len(packets)


@pytest.mark.parametrize("sid", IDS)
def test_labels_cover_a_real_span_inside_the_capture(sid: str) -> None:
    labels = catalogue.load_labels(sid)
    packets = read_pcap(sid)
    first, last = packets[0][0], packets[-1][0]

    assert labels["scenario"] == sid
    assert labels["seed"] == scenario(sid)["seed"]
    assert labels["synthesised"] is True
    assert labels["emulates"] and labels["stands_in_for"]
    assert labels["capture"]["packets"] == len(packets)
    assert abs(labels["capture"]["first_ts"] - first) < 1e-3
    assert abs(labels["capture"]["last_ts"] - last) < 1e-3

    if sid == "benign":
        assert labels["benign_only"] is True
        assert labels["attacks"] == []
        return

    assert labels["attacks"]
    for attack in labels["attacks"]:
        assert attack["threat_class"] in THREAT_CLASSES
        assert attack["threat_class"] != "benign"
        assert attack["subtype"]
        assert attack["expected_signal"]
        assert first <= attack["start_ts"] < attack["end_ts"] <= last
        assert attack["end_ts"] - attack["start_ts"] >= 5.0
        assert attack["attackers"]
        assert attack["victims"]
        assert attack["protocol"] in ("tcp", "udp", "icmp")
    assert labels["threat_class"] in {a["threat_class"] for a in labels["attacks"]}


@pytest.mark.parametrize("sid", IDS)
def test_labelled_endpoints_are_present_in_the_capture(sid: str) -> None:
    labels = catalogue.load_labels(sid)
    if not labels["attacks"]:
        return
    seen = set()
    for _ts, buf in read_pcap(sid):
        ip = dpkt.ethernet.Ethernet(buf).data
        seen.add(".".join(str(b) for b in ip.src))
        seen.add(".".join(str(b) for b in ip.dst))
    for attack in labels["attacks"]:
        assert seen & set(attack["attackers"]), attack["subtype"]
        assert seen & set(attack["victims"]), attack["subtype"]


@pytest.mark.parametrize("sid", IDS)
def test_attack_windows_are_embedded_in_background_traffic(sid: str) -> None:
    labels = catalogue.load_labels(sid)
    if not labels["attacks"]:
        return
    marked = set()
    for attack in labels["attacks"]:
        marked |= set(attack["attackers"]) | set(attack["victims"])
    others = 0
    for _ts, buf in read_pcap(sid):
        ip = dpkt.ethernet.Ethernet(buf).data
        src = ".".join(str(b) for b in ip.src)
        dst = ".".join(str(b) for b in ip.dst)
        if src not in marked and dst not in marked:
            others += 1
    assert others > 500, "attack traffic must sit inside benign background, not alone"


def test_the_two_exfiltration_shapes_are_both_in_the_corpus() -> None:
    subtypes = set()
    for sid in IDS:
        labels = catalogue.load_labels(sid)
        for attack in labels["attacks"]:
            if attack["threat_class"] == "data-exfiltration":
                subtypes.add(attack["subtype"])
    assert any("drip" in s for s in subtypes), subtypes
    assert any("bulk" in s for s in subtypes), subtypes


def test_index_matches_the_generated_files() -> None:
    with open(catalogue.INDEX_FILE, "r", encoding="utf-8") as fh:
        index = json.load(fh)
    assert set(index) == set(IDS)
    for sid, info in index.items():
        path = catalogue.abspath(scenario(sid)["file"])
        assert info["pcap_size"] == os.path.getsize(path)
        assert len(info["pcap_sha256"]) == 64
        assert info["seed"] == scenario(sid)["seed"]


def test_tls_profiles_are_published_for_the_reference_table() -> None:
    path = os.path.join(catalogue.SCENARIO_DIR, "tls_profiles.json")
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    assert set(payload["profiles"]) == {"chrome-windows", "firefox-linux", "safari-macos"}
    assert set(payload["os_profiles"]) == {"windows", "linux", "macos"}
    assert payload["os_profiles"]["windows"]["ttl"] == 128
    assert payload["os_profiles"]["linux"]["ttl"] == 64


def test_load_labels_rejects_an_unknown_scenario() -> None:
    with pytest.raises(KeyError):
        catalogue.load_labels("not-a-scenario")

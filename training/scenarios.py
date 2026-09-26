from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIO_DIR = os.path.join(ROOT, "data", "scenarios")
INDEX_FILE = os.path.join(SCENARIO_DIR, "index.json")

SYNTHESIS_NOTE = (
    "every pcap in data/scenarios was synthesised packet by packet with dpkt.pcap.Writer by "
    "training/generate_scenarios.py. no attack tool was run to produce them and none is needed to "
    "regenerate them. the tools named below are what each scenario emulates, not what made it."
)

EMULATION = [
    {
        "id": "benign",
        "emulates": "mixed web, dns, tls and bulk office traffic across 40 internal hosts",
        "stands_in_for": "iperf3 / Ostinato / TRex benign load generation",
        "note": "false-positive baseline, must score zero alerts",
    },
    {
        "id": "syn_flood",
        "emulates": "spoofed-source tcp syn flood against one victim service",
        "stands_in_for": "hping3 -S --flood --rand-source",
        "note": "source entropy explodes, syn:syn-ack ratio blows up",
    },
    {
        "id": "udp_reflection",
        "emulates": "dns ANY and ntp monlist reflection off a small resolver set",
        "stands_in_for": "hping3 --udp spoofed at open resolvers",
        "note": "source entropy collapses, amplification ratio is the tell",
    },
    {
        "id": "slowloris",
        "emulates": "many long-lived half-open http requests held open with header drips",
        "stands_in_for": "slowloris.pl / slowhttptest -H",
        "note": "low packet rate, very high concurrency, no completed requests",
    },
    {
        "id": "beacon_jitter",
        "emulates": "http/tls c2 check-in every 45 s with plus or minus 30 percent jitter",
        "stands_in_for": "a sandboxed c2 emulator such as a Cobalt Strike sleep+jitter profile",
        "note": "carries benign update-poller decoys at 300 s with plus or minus 45 percent jitter",
    },
    {
        "id": "dga_burst",
        "emulates": "nxdomain bursts from one algorithmic dga family and one dictionary family",
        "stands_in_for": "DGArchive name lists replayed as dns queries",
        "note": "the dictionary family has normal character entropy on purpose",
    },
    {
        "id": "dns_tunnel",
        "emulates": "base32 encoded subdomains under one registered domain, txt and null answers",
        "stands_in_for": "iodine / dnscat2",
        "note": "subdomain cardinality survives any payload encoding change",
    },
    {
        "id": "ja4_spoof",
        "emulates": "tls clienthello claiming chrome-on-windows from a host whose syn is linux",
        "stands_in_for": "a tls client library with a copied chrome fingerprint (utls style)",
        "note": "cross-layer disagreement, needs no destination reputation data",
    },
    {
        "id": "port_scan",
        "emulates": "fast vertical syn scan, slow vertical scan and a horizontal sweep on 445",
        "stands_in_for": "nmap -sS -T4, nmap -T1, and a custom slow sweep script",
        "note": "three fan-out shapes that must not be collapsed into one counter",
    },
    {
        "id": "exfil_drip",
        "emulates": "small outbound chunks every 20 s sustained for 30 minutes to one destination",
        "stands_in_for": "a chunked-upload staging script over https",
        "note": "no single window crosses a volume threshold, the ewma of the ratio does",
    },
    {
        "id": "exfil_bulk",
        "emulates": "staged uploads to one destination followed by a 5 megabyte transfer in one minute",
        "stands_in_for": "rclone or curl pushing a staged archive over https",
        "note": "the other exfiltration shape: the volume is all in one window, not spread across many",
    },
]

_CATALOGUE = [
    {
        "id": "benign",
        "name": "Benign baseline",
        "threat_class": "benign",
        "proves": "false-positive rate and steady-state memory: this one must raise zero alerts",
        "seed": 26145001,
        "duration_s": 300,
    },
    {
        "id": "syn_flood",
        "name": "Spoofed-source SYN flood",
        "threat_class": "volumetric-ddos",
        "proves": "source-IP entropy explosion plus a runaway SYN:SYN-ACK ratio",
        "seed": 26145002,
        "duration_s": 180,
    },
    {
        "id": "udp_reflection",
        "name": "DNS and NTP reflection",
        "threat_class": "volumetric-ddos",
        "proves": "the other DDoS sub-type: entropy collapse and a high amplification ratio",
        "seed": 26145003,
        "duration_s": 180,
    },
    {
        "id": "slowloris",
        "name": "Slowloris connection exhaustion",
        "threat_class": "volumetric-ddos",
        "proves": "low-rate protocol exhaustion that a packets-per-second threshold never sees",
        "seed": 26145004,
        "duration_s": 600,
    },
    {
        "id": "beacon_jitter",
        "name": "Jittered C2 beacon",
        "threat_class": "c2-beaconing",
        "proves": "Lomb-Scargle recovers a 45 s period under plus or minus 30 percent jitter",
        "seed": 26145005,
        "duration_s": 3600,
    },
    {
        "id": "dga_burst",
        "name": "DGA burst, algorithmic and dictionary",
        "threat_class": "dga-dns-tunnelling",
        "proves": "why character entropy alone is insufficient: the dictionary family looks normal",
        "seed": 26145006,
        "duration_s": 600,
    },
    {
        "id": "dns_tunnel",
        "name": "DNS tunnelling over TXT and NULL",
        "threat_class": "dga-dns-tunnelling",
        "proves": "subdomain cardinality per registered domain survives base32 encoding evasion",
        "seed": 26145007,
        "duration_s": 600,
    },
    {
        "id": "ja4_spoof",
        "name": "JA4-spoofed TLS from a Linux host",
        "threat_class": "encrypted-malware",
        "proves": "cross-layer disagreement between the TLS fingerprint and the TCP fingerprint",
        "seed": 26145008,
        "duration_s": 600,
    },
    {
        "id": "port_scan",
        "name": "Fast, slow and horizontal scanning",
        "threat_class": "recon-scanning",
        "proves": "multi-scale windows catch the slow scan, fan-out shape names which scan it was",
        "seed": 26145009,
        "duration_s": 600,
    },
    {
        "id": "exfil_drip",
        "name": "Slow-drip exfiltration",
        "threat_class": "data-exfiltration",
        "proves": "an EWMA of the outbound:inbound ratio beats a single-window byte threshold",
        "seed": 26145010,
        "duration_s": 1800,
    },
    {
        "id": "exfil_bulk",
        "name": "Bulk upload exfiltration",
        "threat_class": "data-exfiltration",
        "proves": "the burst sub-type: the same ratio rule separates one big window from a drip",
        "seed": 26145011,
        "duration_s": 900,
    },
]


def _read_index() -> dict:
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _build() -> list[dict]:
    index = _read_index()
    out = []
    for spec in _CATALOGUE:
        sid = spec["id"]
        observed = index.get(sid, {})
        out.append(
            {
                "id": sid,
                "name": spec["name"],
                "file": f"data/scenarios/{sid}.pcap",
                "flow_file": f"data/scenarios/{sid}.flows.csv",
                "labels_file": f"data/scenarios/{sid}.labels.json",
                "proves": spec["proves"],
                "threat_class": spec["threat_class"],
                "seed": spec["seed"],
                "packets": int(observed.get("packets", 0)),
                "duration_s": float(observed.get("duration_s", spec["duration_s"])),
                "nominal_duration_s": int(spec["duration_s"]),
                "bytes": int(observed.get("bytes", 0)),
                "flow_records": int(observed.get("flow_records", 0)),
            }
        )
    return out


SCENARIOS = _build()

FLOW_COLUMNS = [
    "ts_start",
    "ts_end",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "packets",
    "bytes",
    "tcp_flags",
    "direction_hint",
]


def get(scenario_id: str) -> dict:
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    raise KeyError(scenario_id)


def abspath(rel: str) -> str:
    return os.path.join(ROOT, rel.replace("/", os.sep))


def load_labels(scenario_id: str) -> dict:
    with open(abspath(get(scenario_id)["labels_file"]), "r", encoding="utf-8") as fh:
        return json.load(fh)


def reload() -> list[dict]:
    global SCENARIOS
    SCENARIOS = _build()
    return SCENARIOS

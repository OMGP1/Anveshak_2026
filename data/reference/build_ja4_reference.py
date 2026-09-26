from __future__ import annotations

import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from engine.decode.tcp_fingerprint import fingerprint_family, tcp_fingerprint  # noqa: E402
from engine.sources.pcap_source import PcapSource  # noqa: E402

PROFILES_FILE = os.path.join(ROOT, "data", "scenarios", "tls_profiles.json")
BASELINE_PCAP = os.path.join(ROOT, "data", "scenarios", "benign.pcap")
OUT_FILE = os.path.join(HERE, "ja4_tcp_reference.json")

LABELS = {
    "chrome-windows": "Chrome on Windows",
    "firefox-linux": "Firefox on Linux",
    "safari-macos": "Safari on macOS",
}


def os_profile_fingerprints(src: dict) -> dict[str, tuple[str, str]]:
    out = {}
    for os_name, profile in src["os_profiles"].items():
        names = ",".join(opt[0] for opt in profile["opts"])
        fp = "{0}:{1}:{2}:{3}".format(profile["ttl"], profile["win"], profile["mss"], names)
        out[fp] = (os_name, profile["tls"])
    return out


def observe_baseline() -> tuple[dict[int, str], dict[int, str]]:
    ja4_by_host: dict[int, str] = {}
    fp_by_host: dict[int, str] = {}
    for meta in PcapSource(BASELINE_PCAP):
        fp = tcp_fingerprint(meta)
        if fp:
            fp_by_host.setdefault(meta.src_ip, fp)
        if meta.tls is not None and meta.tls.is_client_hello:
            ja4_by_host.setdefault(meta.src_ip, meta.tls.ja4)
    return ja4_by_host, fp_by_host


def build() -> dict:
    with open(PROFILES_FILE, "r", encoding="ascii") as fh:
        profiles = json.load(fh)
    by_fp = os_profile_fingerprints(profiles)
    ja4_by_host, fp_by_host = observe_baseline()
    pairs: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for host, ja4 in ja4_by_host.items():
        fp = fp_by_host.get(host)
        if fp:
            pairs[ja4][fp] += 1
    families: dict[str, dict] = {}
    for ja4, counter in pairs.items():
        fp, support = counter.most_common(1)[0]
        os_name, tls_name = by_fp.get(fp, ("unknown", "unknown"))
        families[ja4] = {
            "label": LABELS.get(tls_name, tls_name),
            "tls_profile": tls_name,
            "expected_tcp_families": sorted({fingerprint_family(f) for f in counter}),
            "reference_tcp_fingerprint": fp,
            "reference_os": os_name,
            "support_hosts": int(sum(counter.values())),
            "agreeing_hosts": int(support),
            "confidence": round(support / sum(counter.values()), 3),
        }
    return {
        "version": "1.0.0",
        "derived_from": "data/scenarios/benign.pcap parsed with engine.decode.tls and "
                        "engine.decode.tcp_fingerprint, labelled against data/scenarios/tls_profiles.json",
        "method": "the benign baseline capture is spoof-free by construction, so the ja4 to tcp "
                  "fingerprint pairing observed there is the ground-truth pairing for this enclave",
        "unknown_policy": "a ja4 absent from this table produces no claim and no rule alert. the "
                          "detector falls back to the online co-occurrence learner instead",
        "coverage_note": "three tls stacks only, learned from one local capture. this is not a survey "
                         "of real-world ja4 values and must not be presented as one",
        "macos_note": "safari on macos pairs with a bsd-family tcp stack, which is what the darwin "
                      "kernel presents",
        "families": families,
    }


def main() -> None:
    table = build()
    with open(OUT_FILE, "w", encoding="ascii") as fh:
        json.dump(table, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for ja4, row in sorted(table["families"].items()):
        print(ja4, "->", row["label"], row["expected_tcp_families"], "hosts", row["support_hosts"])


if __name__ == "__main__":
    main()

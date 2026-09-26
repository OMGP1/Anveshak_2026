"""Defensive method inventory. Method names are not packet signatures."""

SOURCE = "https://github.com/MatrixTM/MHDDoS/blob/main/start.py"
REVIEWED = "2026-09-07"

LAYER7 = "CFB BYPASS GET POST OVH STRESS DYN SLOW HEAD NULL COOKIE PPS EVEN GSB DGB AVB CFBUAM APACHE XMLRPC BOT BOMB DOWNLOADER KILLER TOR RHEX STOMP".split()
AMPLIFICATION = "MEM NTP DNS ARD CLDAP CHAR RDP".split()
TRANSPORT = "TCP UDP SYN VSE MINECRAFT MCBOT CONNECTION CPS FIVEM FIVEM-TOKEN TS3 MCPE ICMP OVH-UDP".split()
AMPLIFICATION_PORTS = {"MEM": 11211, "NTP": 123, "DNS": 53, "ARD": 3283,
                       "CLDAP": 389, "CHAR": 19, "RDP": 3389}


def method_coverage(config: dict | None = None, *, source_kind: str | None = None) -> dict:
    settings = (config or {}).get("detectors", {}).get("ddos", {}).get("protocol_flood", {})
    enabled = bool(settings.get("enabled", False))
    packet_timing = source_kind != "flows"
    active = enabled and packet_timing
    syn_enabled = active and float(settings.get("minimum_syn_pps", 0)) > 0
    methods = []
    for name in sorted(LAYER7 + AMPLIFICATION + TRANSPORT):
        detector_enabled = True
        validation = "No exact tool-method validation"
        if name == "SYN":
            status, family = "family-tested-synthetic", "SYN flood"
            note = "Existing rule has a synthetic regression fixture; no MHDDoS capture was executed."
        elif name in AMPLIFICATION:
            status, family = "partial-metadata", "UDP amplification"
            note = "Aggregate reflection evidence can trigger. Seven service-port variants of one synthetic reflection shape are tested; this does not validate protocol semantics or tool attribution."
            validation = "Synthetic aggregate reflection with service-port substitution"
        elif name == "CPS":
            status, family = "partial-metadata", "TCP connection-attempt rate"
            note = "Optional SYN-attempt rate detects churn below the packet-rate floor. SYN retransmissions are not distinct or completed connections."
            detector_enabled = syn_enabled
            validation = "Offline SYN-attempt metadata fixture; no MHDDoS execution"
        elif name in ("SLOW", "CONNECTION"):
            status, family = "partial-metadata", "Connection exhaustion"
            note = "Existing half-open and teardown heuristics may trigger. Slow application reads and established-connection exhaustion need richer telemetry."
        elif name in TRANSPORT:
            status, family = "experimental-rate-only", "Transport rate anomaly"
            note = "Optional TCP/UDP/ICMP rate monitoring flags baseline deviations or configured absolute limits. It does not identify game protocols, clients, or tool names."
            detector_enabled = active
            validation = "Offline transport-rate fixtures only"
        else:
            status, family = "not-distinguishable", "Application-layer behavior"
            note = "Encrypted HTTP method, path, header, challenge, and content differences are not available to this passive metadata engine."
            detector_enabled = False
        methods.append({"method": name, "family": family, "status": status, "note": note,
                        "detector_enabled": detector_enabled, "validation": validation,
                        "exact_method_validated": False})
    return {"source": SOURCE, "reviewed": REVIEWED, "registered_methods": len(methods),
            "note": "Source method sets contain 47 names; the repository headline advertises 57. No universal detection claim.",
            "exact_methods_validated": 0,
            "runtime": {"extended_configured": enabled, "extended_enabled": active,
                        "syn_attempt_enabled": syn_enabled, "source_kind": source_kind,
                        "note": "Enabled means a family heuristic is available, not that every method is detected. "
                                "Extended packet-rate alarms skip aggregate flow exports."},
            "methods": methods}

"""Minimum observable evidence for model-only alerts, before confidence or anomaly gates."""
from __future__ import annotations


def supports_class(name: str, values: dict, minimum_exfil_bytes: float = 100_000) -> bool:
    def value(key):
        return float(values.get(key, 0.0))

    if name == "encrypted-malware":
        return (value("tls_version") > 0 and value("ja4_observation_count") > 0
                and "fingerprint_consistency_score" in values)
    if name == "recon-scanning":
        return value("scan_probe_count_60s") > 1
    if name == "c2-beaconing":
        return value("beacon_sample_count") >= 3 and value("ls_peak_period_s") > 0
    if name == "data-exfiltration":
        return value("outbound_bytes_total") >= minimum_exfil_bytes and value("out_in_ratio_ewma") > 1
    if name == "dga-dns-tunnelling":
        return value("source_query_count_300s") > 1 and (
            value("distinct_regdom_300s") > 1
            or (value("subdomain_cardinality") > 1 and value("qtype_txt_null_ratio") > 0))
    if name == "volumetric-ddos":
        return value("pps_to_dst_ewma_dev") > 0 and (
            value("syn_synack_ratio_1s") > 1
            or (value("udp_packet_share") >= 0.8 and value("reflection_service_share") >= 0.8)
            or (value("udp_packet_share") >= 0.8 and value("entropy_explosion_score") >= 0.5))
    return False

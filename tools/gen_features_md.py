from __future__ import annotations

import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.features import registry  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "FEATURES.md")

GROUP_TITLE = {
    "flow-structural": "Flow-structural",
    "ddos": "Volumetric and protocol DDoS, class (a)",
    "beaconing": "Botnet C2 beaconing, class (b)",
    "dga-dns": "DGA domains and DNS tunnelling, class (c)",
    "encrypted": "Malware in encrypted sessions, class (d)",
    "scan": "Reconnaissance and port scanning, class (e)",
    "exfil": "Data exfiltration, class (f)",
    "context": "Detection context",
}

GROUP_NOTE = {
    "flow-structural": "Read by every detector. Threat class is 'all' because these describe the "
                       "flow, not an attack.",
    "ddos": "The PS names flow rate statistics and source-IP entropy for this class. Both are here, "
            "plus the two features that tell the sub-types apart.",
    "beaconing": "The PS names periodicity and inter-arrival analysis. The periodogram features are "
                 "computed only for candidates that pass the beacon pre-filter.",
    "dga-dns": "The PS names entropy and n-gram analysis of query names. The campaign-level counters "
               "are here because the n-gram score alone does not separate the dictionary family.",
    "encrypted": "TLS metadata only. Nothing in this group is derived from application data, and no "
                 "feature here needs a lookup of any kind.",
    "scan": "The PS names fan-out across ports or hosts. Vertical, horizontal and strobe fan-out are "
            "kept as three separate features so an alert can say which pattern fired.",
    "exfil": "The PS names asymmetric outbound-to-inbound byte ratios. Orientation comes from the "
             "flow table, so no notion of an inside subnet is needed.",
    "context": "Emitted into every alert so that a detection raised under load says so.",
}


def wrap(text: str, width: int = 96) -> str:
    return textwrap.fill(" ".join(text.split()), width=width)


def render() -> str:
    lines: list[str] = []
    lines.append("# Feature Dictionary")
    lines.append("")
    lines.append("Generated from `engine/features/registry.py` by `tools/gen_features_md.py`. Do not")
    lines.append("edit this file by hand: edit the registry and regenerate, otherwise the")
    lines.append("documentation and the code drift apart.")
    lines.append("")
    lines.append("    python tools/gen_features_md.py")
    lines.append("")
    lines.append("This is deliverable requirement R14. Every feature the engine computes is listed")
    lines.append("here with its definition, the reason it exists, and the threat class it serves.")
    lines.append("A test in `tests/test_detectors.py` asserts that every feature any detector emits,")
    lines.append("and every feature name that appears in any alert's evidence, is present in the")
    lines.append("registry, so this list cannot fall behind the code.")
    lines.append("")
    lines.append(f"Feature count: **{registry.COUNT}**.")
    lines.append("")
    lines.append(wrap(registry.COUNT_NOTE + "."))
    lines.append("")
    lines.append("| Group | Features |")
    lines.append("|---|---|")
    for group in registry.GROUPS:
        lines.append(f"| {GROUP_TITLE[group]} | {len(registry.FEATURES_BY_GROUP[group])} |")
    lines.append(f"| **Total** | **{registry.COUNT}** |")
    lines.append("")
    for group in registry.GROUPS:
        rows = registry.FEATURES_BY_GROUP[group]
        if not rows:
            continue
        lines.append(f"## {GROUP_TITLE[group]}")
        lines.append("")
        lines.append(wrap(GROUP_NOTE[group]))
        lines.append("")
        for row in rows:
            lines.append(f"**`{row['name']}`** - {row['dtype']} - {row['threat_class']}")
            lines.append("")
            lines.append(wrap(row["definition"] + "."))
            lines.append("")
            lines.append(wrap("Why: " + row["rationale"] + "."))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    text = render()
    with open(OUT, "w", encoding="ascii", newline="\n") as handle:
        handle.write(text)
    print(f"wrote {OUT} ({registry.COUNT} features)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
